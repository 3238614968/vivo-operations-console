import concurrent.futures
import json
import threading
import time
import pytest
import requests
from protocol.transport import Transport,AccountStop


def response(code=0,http=200):
    value=requests.Response();value.status_code=http;value._content=json.dumps({'code':code}).encode();return value


def test_safe_query_recovers_transient_failure_without_failed_task_observation(monkeypatch):
    calls=[]
    def request(*args,**kwargs):
        calls.append(1)
        if len(calls)==1:raise requests.ConnectTimeout('synthetic timeout')
        return response()
    monkeypatch.setattr(requests.Session,'request',request)
    transport=Transport(gap=0);transport.retry_backoff=0
    assert transport.get('https://pointh5.vivo.com.cn/api/task/list.do').json()['code']==0
    assert len(calls)==2 and transport.retries_count==1 and transport.observations==[]


@pytest.mark.parametrize('path,method',[('/api/task/receivePoint.do','POST'),('/wukongapc/lottery/draw','POST'),('/api/activity/guess/v2/receive.do','GET')])
def test_mutations_are_not_retried_even_when_get_is_used(monkeypatch,path,method):
    calls=[]
    def request(*a,**k):calls.append(1);raise requests.ReadTimeout('synthetic timeout')
    monkeypatch.setattr(requests.Session,'request',request)
    with pytest.raises(requests.ReadTimeout):Transport(gap=0).request(method,'https://pointh5.vivo.com.cn'+path)
    assert len(calls)==1


def test_platform_verification_stops_without_retry(monkeypatch):
    calls=[]
    def request(*a,**k):calls.append(1);return response(1050)
    monkeypatch.setattr(requests.Session,'request',request)
    with pytest.raises(AccountStop):Transport(gap=0).get('https://pointh5.vivo.com.cn/api/task/list.do')
    assert len(calls)==1


def test_async_account_sessions_never_share_cookie_jars(client):
    from protocol.runner import transport_for,make_api
    barrier=threading.Barrier(3)
    def work(index):
        transport=transport_for({'mode':'live','proxy':{},'request_gap':.6})
        make_api({'openid':f'account-{index}','vivotoken':f'token-{index}'},transport)
        barrier.wait(timeout=5)
        return id(transport),transport.cookies.get('vvc_r')
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:results=list(pool.map(work,range(3)))
    assert len({result[0] for result in results})==3
    assert {result[1] for result in results}=={'token-0','token-1','token-2'}


def test_claim_many_assigns_distinct_accounts_and_exits_atomically(client):
    from adapter import import_accounts
    from store import db,now
    from executor import claim_many
    import_accounts('live',[{'openid':f'async-{i}','vivotoken':'test'} for i in range(4)])
    with db('live') as c:
        for i in range(3):c.execute("INSERT INTO proxies(fingerprint,url,source,status,exit_ip,created_at) VALUES(?,?,'user','healthy',?,?)",(str(i),f'socks5h://8.8.8.{i}:1080',f'8.8.8.{i}',now()))
        c.execute("INSERT INTO batches VALUES('async','test','full','running',4,4,?,NULL)",(now(),))
        c.executemany("INSERT INTO runs(batch_id,account_id) VALUES('async',?)",[(i,) for i in range(1,5)])
    jobs=claim_many('live','async',4,4)
    assert len(jobs)==3 and len({job[1] for job in jobs})==3
    with db('live') as c:assert c.execute('SELECT count(*) FROM execution_leases').fetchone()[0]==6


def test_settings_validate_async_capacity_and_allow_empty_import_path(client):
    headers={'X-Data-Mode':'live'}
    assert client.put('/api/settings',headers=headers,json={'reference_path':'','worker_processes':2,'async_slots':4,'concurrency':8,'read_retry_count':2}).status_code==200
    values=client.get('/api/settings',headers=headers).json
    assert values['async_slots']==4 and values['concurrency']==8 and 'items' not in values['proxy_summary']
    assert client.put('/api/settings',headers=headers,json={'async_slots':17}).status_code==400


def test_delayed_verification_does_not_resubmit_write(monkeypatch):
    from protocol.tasks import execute_center
    monkeypatch.setattr(time,'sleep',lambda seconds:None)
    class Api:
        verify_poll_count=2
        def __init__(self):self.reads=0;self.writes=0
        def h5_call(self,*a,**k):
            self.reads+=1
            return {'retcode':0,'data':{'tasks':[{'list':[{'id':1,'name':'浏览任务','taskComplete':self.reads>=3}]}]}}
        def sign_biz_names(self):return {}
        def _tasks_for_pkg(self,pkg):return {}
        def complete_task(self,*a):self.writes+=1;return {'route':'web','claim_accepted':True,'responses':[{'code':0}]}
    api=Api();result=execute_center(api,['com.vivo.space'])
    assert api.writes==1 and result['completed']==1


def test_async_process_has_parallel_slots_and_cleans_up_failed_jobs(client,monkeypatch):
    from pathlib import Path
    import store
    from async_pool import AsyncProcessPool
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'scripts'))
    pool=AsyncProcessPool(1,3,str(store.DATA),'benchmark_async:simulate')
    try:
        futures=[pool.submit(None,'fake',i,.18) for i in range(3)]
        values=[f.result(timeout=15) for f in futures]
        assert len({r['pid'] for r in values})==1
        assert max(r['started'] for r in values)<min(r['finished'] for r in values)
        failure=pool.submit(None,'fake',99,0,True)
        with pytest.raises(RuntimeError,match='账号执行异常'):failure.result(timeout=5)
        assert pool.submit(None,'fake',100,0).result(timeout=5)['id']==100
    finally:pool.shutdown(wait=True)
    assert not any(process.is_alive() for process in pool.processes)


def test_dead_worker_releases_waiting_futures(client,monkeypatch):
    from pathlib import Path
    from concurrent.futures.process import BrokenProcessPool
    import store
    from async_pool import AsyncProcessPool
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'scripts'))
    pool=AsyncProcessPool(1,2,str(store.DATA),'benchmark_async:simulate')
    try:
        future=pool.submit(None,'fake',1,3)
        pool.processes[0].terminate();pool.processes[0].join(timeout=3)
        with pytest.raises(BrokenProcessPool):future.result(timeout=5)
        assert pool.broken
    finally:pool.shutdown(wait=True)


def test_balance_sync_preserves_task_status_and_last_task_gain(client):
    import engine
    from store import db
    with db('demo') as c:c.execute("UPDATE accounts SET gained=99,task_status='partial',last_run='2026-10-15T12:00:00+08:00' WHERE id=1")
    bid=engine.create_batch('demo','sync',ids=[1],start_paused=True)
    with db('demo') as c:rid=c.execute('SELECT id FROM runs WHERE batch_id=?',(bid,)).fetchone()[0]
    engine.run_one('demo',rid,'sync')
    with db('demo') as c:
        account=c.execute('SELECT gained,task_status,last_run FROM accounts WHERE id=1').fetchone()
        run=c.execute('SELECT status,gained FROM runs WHERE id=?',(rid,)).fetchone()
    assert tuple(account)==(99,'partial','2026-10-15T12:00:00+08:00')
    assert tuple(run)==('completed',0)


def test_old_timestamp_does_not_force_valid_token_renewal(client,monkeypatch):
    import engine
    from adapter import import_accounts
    from store import db
    import_accounts('live',[{'openid':'old-valid','vivotoken':'valid','saved_at':time.time()-6*86400}])
    observed=[]
    def events(mode,account,**kwargs):
        observed.append(kwargs['refresh_login'])
        yield {'type':'balance','points':1}
        yield {'type':'result','points':1,'before':1,'gained':0}
    monkeypatch.setattr(engine,'live_events',events)
    bid=engine.create_batch('live','sync',ids=[1],start_paused=True)
    with db('live') as c:rid=c.execute('SELECT id FROM runs WHERE batch_id=?',(bid,)).fetchone()[0]
    engine.run_one('live',rid,'sync')
    assert observed==[False]


def test_resume_cannot_overfill_another_running_batch(client,monkeypatch):
    import engine
    monkeypatch.setattr(engine,'launch',lambda *args:None)
    paused=engine.create_batch('demo','sync',ids=[1],start_paused=True)
    engine.create_batch('demo','sync',ids=[2],validation=True)
    with pytest.raises(ValueError,match='已有执行中的批次'):engine.control('demo',paused,'resume')


def test_reused_session_records_only_current_sync_request_count(monkeypatch):
    import protocol.runner as runner
    transport=Transport(gap=0)
    class Api:
        identity_ok=staticmethod(runner.VivoApi.identity_ok)
        ok=staticmethod(lambda value:value.get('code')==0)
        def user_info(self):transport.requests_count+=1;return {'code':0}
        def pm_points(self):transport.requests_count+=1;return 10
    monkeypatch.setattr(runner,'transport_for',lambda payload:transport)
    monkeypatch.setattr(runner,'make_api',lambda raw,s:Api())
    counts=[]
    for _ in range(2):
        events=list(runner.iter_events({'account':{'openid':'sample','vivotoken':'test'},'profile':'sync'}))
        counts.append(next(event['request_count'] for event in events if event['type']=='step'))
    assert counts==[2,2]
