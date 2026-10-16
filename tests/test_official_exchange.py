from contextlib import nullcontext
from types import SimpleNamespace
import json
from store import db,now

def test_pointstore_plain_json_contract():
    from protocol.market import mall_call
    calls=[]
    api=SimpleNamespace(_h5_headers=lambda package:{'cookie':'vvc_openid=own;vvc_r=own-token'},s=SimpleNamespace(request=lambda *a,**kw:(calls.append((a,kw)) or SimpleNamespace(json=lambda:{'retcode':0}))))
    payload={'itemId':31443,'categoryId':'120','arpuId':'','cpdTaskKeyId':'','pts_sys_ver':'20260626_v6.1.4','channel':'point','source':0}
    mall_call(api,{'redemption_kind':'standard','categoryId':120,'city':'全国'},'/api/mall/item/exchange.do',payload,'POST')
    args,kw=calls[0]
    assert args==('POST','https://pointwap.vivo.com.cn/api/mall/item/exchange.do')
    assert kw['json']==payload and kw['headers']['Origin']=='https://pointstore.vivo.com.cn'
    assert 'vivo_member_source_type=APP_H5' in kw['headers']['cookie']

def test_standard_order_can_finish_without_sms_and_collect_activation(client,monkeypatch):
    import protocol.runner as runner
    import protocol.market as market
    from protocol.transport import Transport
    calls=[]
    class Api:
        identity_ok=staticmethod(runner.VivoApi.identity_ok)
        def user_info(self):return {'retcode':0}
        def ok(self,v):return v.get('retcode')==0
        def pm_points(self):return 100
        def pm_categories(self):return []
        def _pm_enc(self,*a):raise AssertionError('Standard order must use pointstore JSON')
    monkeypatch.setattr(runner,'make_api',lambda *a:Api());monkeypatch.setattr(runner,'transport_for',lambda *a:Transport())
    monkeypatch.setattr(market,'current_offer',lambda *a:{'price':5,'stock':10,'metadata':{'itemId':31443,'categoryId':120,'redemption_kind':'standard'}})
    def call(api,meta,path,params=None,method='GET'):
        calls.append((path,params,method));return {'retcode':0,'data':{'orderId':88,'points':95}}
    monkeypatch.setattr(market,'mall_call',call)
    monkeypatch.setattr(market,'order_details',lambda *a:{'points':95,'order':{'id':88,'redeemCode':'TEST-CODE','deliveryInfo':'TEST-CODE','expireTime':1793462399000},'item':{}})
    events=list(runner.iter_events({'mode':'live','action':'exchange','account':{'openid':'own','vivotoken':'own-token'},'account_id':1,'product':{},'expected_price':5}))
    assert events[-1]['status']=='success' and events[-1]['points_after']==95
    assert events[-1]['delivery']['redeemCode']=='TEST-CODE'
    assert len(calls)==1 and not any('sms' in c[0] for c in calls)
    assert not {'scene','ticket','constId','jvq_param'}&calls[0][1].keys()
    assert calls[0][1]['pts_sys_ver']=='20260626_v6.1.4'

def test_preflight_does_not_require_sms_by_default(client,monkeypatch):
    import commerce
    from adapter import import_accounts
    import_accounts('live',[{'openid':'own','vivotoken':'own-token'}])
    with db('live') as c:c.execute("INSERT INTO products(id,name,category,price,stock,source,updated_at) VALUES('x','ebook','c',5,10,'live',?)",(now(),))
    monkeypatch.setattr(commerce,'lease',lambda *a:nullcontext(None))
    monkeypatch.setattr(commerce,'preview_with_proxy',lambda *a:{'points':100,'product':{'price':5,'stock':10,'metadata':{'redemption_kind':'standard'}}})
    result=client.post('/api/redemptions/preflight',headers={'X-Data-Mode':'live'},json={'account_id':1,'product_id':'x'})
    assert result.status_code==200 and result.json['sms_required'] is False

def test_refresh_activation_never_redeems_or_deducts(client,monkeypatch):
    import commerce
    from adapter import import_accounts
    import_accounts('live',[{'openid':'own','vivotoken':'own-token'}])
    with db('live') as c:
        c.execute('UPDATE accounts SET points=95')
        c.execute("INSERT INTO products(id,name,category,price,stock,source,updated_at) VALUES('x','ebook','c',5,9,'live',?)",(now(),))
        c.execute("INSERT INTO redemptions(id,idempotency_key,account_id,product_id,product_name,price,status,remote_order,created_at) VALUES('EX1','r1',1,'x','ebook',5,'success','88',?)",(now(),))
    monkeypatch.setattr(commerce,'lease',lambda *a:nullcontext(None))
    def events(*a,**kw):
        assert kw['action']=='exchange_order' and kw['order_id']=='88'
        yield {'type':'exchange_order','delivery':{'redeemCode':'TEST-CODE'}}
    monkeypatch.setattr(commerce,'live_events',events)
    result=client.post('/api/redemptions/EX1/refresh',headers={'X-Data-Mode':'live'},json={})
    assert result.status_code==200 and json.loads(result.json['delivery'])['redeemCode']=='TEST-CODE'
    with db('live') as c:
        assert c.execute('SELECT points FROM accounts').fetchone()[0]==95
        assert c.execute('SELECT stock FROM products').fetchone()[0]==9
        assert c.execute('SELECT count(*) FROM redemptions').fetchone()[0]==1
