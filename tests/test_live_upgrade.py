import json
from contextlib import nullcontext
from types import SimpleNamespace
import pytest
from store import db,now,encrypt


def test_catalog_follows_all_pages_and_preserves_zero_price():
    from protocol.market import read_scope
    pages=[]
    class Api:
        def h5_call(self,*args,**kwargs):
            page=kwargs['params']['pageNo'];pages.append(page)
            return {'retcode':0,'data':{'items':[{'id':page,'playMethod':0,'finalPoints':0,'originPoints':100,'store':8,'storeUse':3,'name':'a'}], 'hasNext':'true' if page<9 else 'false'}}
    rows=read_scope(Api(),{'categoryId':120,'city':'全国','channel':'point'})
    assert pages==list(range(1,10)) and len(rows)==9
    assert all(row['price']==0 and row['stock']==5 for row in rows)


def test_catalog_does_not_zero_other_scopes_on_partial_refresh(client):
    from catalog import upsert
    spec={'channel':'point','categoryId':1,'city':'全国'}
    with db('live') as c:
        c.execute("INSERT INTO catalog_jobs(id,account_id,scope,status,created_at) VALUES('a',1,'all','running',?)",(now(),))
        for pid,scope in [('gone','point:1:全国:'),('other','point:2:全国:')]:
            c.execute("INSERT INTO products(id,name,category,price,stock,source,scope_key,seen_job,updated_at) VALUES(?,?,'c',1,10,'live',?,'old',?)",(pid,pid,scope,now()))
    upsert('live','a',spec,[])
    with db('live') as c:
        assert c.execute("SELECT stock FROM products WHERE id='gone'").fetchone()[0]==0
        assert c.execute("SELECT stock FROM products WHERE id='other'").fetchone()[0]==10


def test_proxy_failover_preserves_busy_and_unknown_write_bindings(client):
    from proxies import select_bound_proxy
    from adapter import import_accounts
    import_accounts('live',[{'openid':'proxy-test','vivotoken':'test'}])
    with db('live') as c:
        for idx,status in [(1,'failed'),(2,'healthy')]:
            c.execute('INSERT INTO proxies(id,fingerprint,url,source,status,exit_ip,created_at) VALUES(?,?,?,?,?,?,?)',(idx,str(idx),f'http://8.8.8.{idx}:1080','user',status,f'8.8.8.{idx}',now()))
        c.execute('INSERT INTO proxy_bindings VALUES(1,1,?)',(now(),))
        good=[dict(c.execute('SELECT * FROM proxies WHERE id=2').fetchone())]
        c.execute("INSERT INTO task_journals VALUES(1,'task','write','pending',?,?)",(encrypt({}),now()))
        assert select_bound_proxy(c,1,good,set(),True) is None
        c.execute("UPDATE task_journals SET state='confirmed'")
        assert select_bound_proxy(c,1,good,{'exit:8.8.8.2'},True) is None
        assert select_bound_proxy(c,1,good,set(),True)['id']==2
        assert select_bound_proxy(c,1,good,{'exit:8.8.8.2'},True) is None
        assert c.execute('SELECT count(*) FROM proxy_switches').fetchone()[0]==1


def test_source_journal_survives_restart_and_populates_read_counters(client):
    from protocol.taskflow.added_common import Journal
    from protocol.taskflow.protocol_common import ActionRequired
    def context():return SimpleNamespace(mode='live',account_id=1,credentials={'scopes':{}},persist_scopes=lambda s:None)
    first=context();journal=Journal(first,'news')
    journal.submit('read',lambda:None)
    with pytest.raises(ActionRequired):Journal(context(),'news').submit('read',lambda:pytest.fail('must not replay'))
    journal.confirm('read')
    second=context();journal=Journal(second,'news')
    assert second.credentials['scopes'][journal.namespace]['read']['state']=='confirmed'


def test_redemption_requires_fresh_matching_price_and_does_not_send_twice(client,monkeypatch):
    import commerce
    from adapter import import_accounts
    import_accounts('live',[{'openid':'test','vivotoken':'test'}])
    with db('live') as c:
        c.execute('UPDATE accounts SET points=100')
        c.execute("INSERT INTO products(id,name,category,price,stock,source,updated_at) VALUES('p','p','c',5,3,'live',?)",(now(),))
    monkeypatch.setattr(commerce,'lease',lambda *a,**k:nullcontext(None))
    current={'points':100,'product':{'price':6,'stock':3,'metadata':{}}}
    monkeypatch.setattr(commerce,'preview_with_proxy',lambda *a:current)
    calls=[]
    def execute(*args,**kwargs):
        calls.append(kwargs['action']);yield {'type':'exchange_submit'}
        yield {'type':'exchange','status':'success','remote_order':'real-order','points_after':95}
    monkeypatch.setattr(commerce,'live_events',execute)
    data={'account_id':1,'product_id':'p','idempotency_key':'safe'};headers={'X-Data-Mode':'live'}
    assert client.post('/api/redemptions',headers=headers,json=data).status_code==400
    assert calls==[]
    current['product']['price']=5
    first=client.post('/api/redemptions',headers=headers,json=data)
    second=client.post('/api/redemptions',headers=headers,json=data)
    assert first.json['status']=='success' and first.json['id']==second.json['id']
    assert len(calls)==1


def test_task_source_branches_have_compatible_runtime(client):
    """Every source branch must reach domain validation, never missing shim APIs."""
    import requests
    from protocol.source_bridge import Context,SOURCE_TASKS,run_source
    from protocol.taskflow.protocol_common import ProtocolError
    class Transport:
        guard=None
        def request(self,*a,**k):
            response=requests.Response();response.status_code=200
            response._content=b'{"code":0,"retcode":0,"data":{}}';response.url=a[1]
            return response
    for key,_ in SOURCE_TASKS:
        api=SimpleNamespace(s=Transport(),acct=SimpleNamespace(imei='123456789012345',oaid='test-oaid',openid='test'),pm_points=lambda:100)
        raw={'openid':'test','vivotoken':'test','device':{'model':'test','sdk_int':33,'android_ver':'13'}}
        api.source_context=Context(api,'live',1,raw)
        try:result=run_source(api,key)
        except (KeyError,TypeError,AttributeError,ImportError,NameError) as error:pytest.fail(f'{key}: {type(error).__name__}: {error}')
        assert result['status'] in ('completed','partial','failed','skipped')


def test_protected_new_routes_and_free_defaults(client):
    import app
    anon=app.app.test_client()
    for path in ['/api/tasks/catalog','/api/catalog/jobs','/api/proxies/switches','/captcha/widget']:
        assert anon.get(path).status_code in (401,302)
    data=client.get('/api/tasks/catalog').json
    assert len(data['items'])>=112 and data['spending_tasks_enabled'] is False
    assert all(not item['default_enabled'] for item in data['items'] if item['handler']=='manual-confirmation')


@pytest.mark.parametrize('kind,path', [('standard','/api/mall/item/exchange.do'),('cloud','/api/mall/cloud/exchange.do'),('store','/api/mall/order/vk/doExchange.do')])
def test_redemption_dispatches_correct_contract_and_requires_readback(client,monkeypatch,kind,path):
    import protocol.runner as runner
    import protocol.market as market
    from protocol.transport import Transport
    calls=[]
    class Api:
        identity_ok=staticmethod(runner.VivoApi.identity_ok)
        def __init__(self):self.reads=0
        def user_info(self):return {'retcode':0}
        def ok(self,r):return r.get('retcode')==0
        def pm_points(self):
            self.reads+=1
            return 100 if self.reads==1 else 95
        def pm_categories(self):return []
        def _pm_enc(self,url,body):calls.append((url,body));return {'retcode':0,'data':{'orderId':'confirmed'}}
    monkeypatch.setattr(runner,'make_api',lambda *a:Api())
    monkeypatch.setattr(runner,'transport_for',lambda *a:Transport())
    monkeypatch.setattr(market,'current_offer',lambda *a:{'price':5,'stock':2,'metadata':{'itemId':1,'categoryId':1,'redemption_kind':kind,'type':1,'name':'Gift'}})
    monkeypatch.setattr(market,'stores',lambda *a:[{'code':'S'}])
    monkeypatch.setattr(market,'mall_call',lambda api,meta,url,params=None,method='GET':(calls.append((url,params)) or {'retcode':0,'data':{'orderId':'confirmed'}}))
    events=list(runner.iter_events({'mode':'live','account':{'openid':'a','vivotoken':'test'},'account_id':1,'action':'exchange','product':{},'expected_price':5,'store_code':'S'}))
    assert calls[0][0]==path
    assert events[-1]['status']=='success' and events[-1]['points_after']==95
    if kind=='store':assert calls[0][1]['store']=={'storeCode':'S'} and calls[0][1]['item']['itemPrice']==5


def test_every_business_route_requires_authentication(client):
    import app
    anon=app.app.test_client()
    for rule in app.app.url_map.iter_rules():
        if rule.endpoint in ('login_page','auth_login'):continue
        url=str(rule)
        import re
        url=re.sub(r'<[^>]+>','1',url)
        for method in rule.methods-{'OPTIONS','HEAD'}:
            response=anon.open(url,method=method,json={} if method in ('POST','PUT','PATCH') else None)
            assert response.status_code in (401,302),(url,method,response.status_code)
