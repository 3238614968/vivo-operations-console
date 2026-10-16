"""Native execution pipeline; emits durable step events without invoking external scripts."""
from __future__ import annotations
import hashlib
import json
import os
import re
import time
import threading
from collections import OrderedDict
from .api import Account,VivoApi
from .common import ALL_PKGS
from .transport import Transport,AccountStop,StepTimeout
from .activities import discover_catalog,execute_dynamic,appointment_family
from .auth import renew
from .source_bridge import Context as SourceContext,run_source,run_groups,SOURCE_TASKS
from .task_policy import step_reason,prune_result
from store import db,now,today,DATA

TRANSPORTS=threading.local()
PLAN_VERSION=6


def classify(value):
    if value is None:return 'failed'
    if isinstance(value,(list,tuple)):
        states=[classify(v) for v in value]
        if not states or all(s=='skipped' for s in states):return 'skipped'
        if all(s=='failed' for s in states):return 'failed'
        return 'partial' if any(s in ('failed','partial') for s in states) else 'completed'
    if not isinstance(value,dict):return 'completed'
    if not value:return 'skipped'
    if value.get('status') in ('completed','failed','partial','skipped'):
        state=value['status']
        if state=='completed' and 'packages' in value and 'discovered' in value:return state
        if state in ('completed','skipped') and value.get('results'):
            nested=classify(value['results'])
            if nested in ('failed','partial'):return 'partial'
            if state=='skipped' and nested=='completed':return 'completed'
        return state
    if value.get('status') in ('manual','blocked','pending'):return 'partial'
    if value.get('skip'):return 'skipped'
    if str(value.get('code'))=='20041':return 'skipped' # Server explicitly retired the old wallet sign-in.
    if any(value.get(k) for k in ('_err','err','error','sms_needed')) or value.get('ok') is False:return 'failed'
    for key in ('code','retcode'):
        if value.get(key) is not None and str(value[key]) not in ('0','200','10002','10003'):return 'failed'
    if value.get('res') not in (None,'ok','already') and not value.get('after_signed'):return 'failed'
    if value.get('progressed') or value.get('no_change') or value.get('failed') or value.get('manual') or value.get('blocked') or value.get('unavailable'):return 'partial'
    for key in ('results','data'):
        if value.get(key) and isinstance(value[key],(list,dict)):
            state=classify(value[key])
            if state in ('failed','partial'):return state
            if key=='results' and state=='skipped':return state
    if value.get('results')==[]:return 'skipped'
    if 'tasks' in value and value.get('tasks')==0 and not value.get('done'):return 'skipped'
    if 'free' in value and value.get('free')==0 and not value.get('draws'):return 'skipped'
    if any(k in value for k in ('drawn','claimable','uploaded','new')) and all(not value.get(k) for k in ('drawn','claimable','uploaded','new','rewarded','got','results')):return 'skipped'
    return 'completed'


def safe_log(value):
    sensitive={'token','vivotoken','openid','unionid','authorization','access_token','session_key','stoken','answertoken','aladdintoken','signawardorderno'}
    if isinstance(value,dict):
        return {key:'[已隐藏]' if key.lower() in sensitive or any(word in key.lower() for word in ('token','password','cookie','secret','authorization')) else safe_log(item) for key,item in value.items()}
    if isinstance(value,(list,tuple)):
        return [safe_log(item) for item in value]
    if isinstance(value,str):
        return re.sub(r'(?i)(token|openid|authorization|password)=([^\s&;]+)',r'\1=[已隐藏]',value)
    return value


def transport_for(payload):
    key=json.dumps(payload.get('proxy') or {},sort_keys=True)
    if not hasattr(TRANSPORTS,'items'):TRANSPORTS.items=OrderedDict()
    sessions=TRANSPORTS.items
    transport=sessions.pop(key,None) or Transport(payload.get('proxy'),gap=float(payload.get('request_gap',.6)))
    sessions[key]=transport
    while len(sessions)>4:
        _,old=sessions.popitem(last=False);old.close()
    transport.gap=float(payload.get('request_gap',.6))
    transport.read_retry_count=int(payload.get('read_retry_count',2))
    transport.retry_backoff=float(payload.get('retry_backoff',.5))
    transport.reset_account()
    mode=payload.get('mode','live')
    def cache_get(key):
        with db(mode) as c:row=c.execute('SELECT payload FROM protocol_cache WHERE key=? AND expires_at>?',(key,time.time())).fetchone()
        return json.loads(row[0]) if row else None
    def cache_put(key,value):
        with db(mode) as c:c.execute('INSERT OR REPLACE INTO protocol_cache VALUES(?,?,?)',(key,json.dumps(value,ensure_ascii=False),time.time()+600))
    transport.cache_get=cache_get;transport.cache_put=cache_put
    owner=payload.get('lease_owner')
    transport.guard=None
    if owner:
        def guard():
            with db(mode) as c:n=c.execute('SELECT count(*) FROM execution_leases WHERE owner=? AND expires_at>?',(owner,time.time()+18)).fetchone()[0]
            if n!=2:raise AccountStop('执行租约已失效，停止请求并等待恢复')
        transport.guard=guard
    return transport


def make_api(raw,transport):
    api=VivoApi(Account(raw),proxy=transport.proxies)
    api.s.close();api.s=transport
    from .devices import webview_ua
    transport.headers['User-Agent']=webview_ua(api.acct.device)
    api._install_cookies()
    api.verify_poll_count=2
    api._gap=lambda:None # Transport enforces one consistent per-exit interval.
    # The knowledge base is durable and merged atomically across worker processes.
    def kb_load():
        with db('live') as c:return {r['key'][3:]:json.loads(r['payload']) for r in c.execute("SELECT key,payload FROM protocol_cache WHERE key LIKE 'kb:%'")}
    def kb_save(kb):
        with db('live') as c:c.executemany('INSERT OR REPLACE INTO protocol_cache VALUES(?,?,?)',[('kb:'+str(k),json.dumps(v),253402300799) for k,v in kb.items()])
    api._kb_load=kb_load;api._kb_save=kb_save
    return api


def step_plan(api,profile):
    plan=[('sign.biz','业务签到',api.sign_all),('sign.main','SPA主签到',api.sign_main),('sign.vivop','vivo+第12端',api.sign_vivop),
      ('sign.appointment','预约签到',lambda:run_source(api,'appointment_sign')),('sign.consecutive','连签',lambda:(api.sign_consecutive_info(),api.consecutive_sign_receive())),
      ('sign.notify','签到提醒',lambda:api.sign_notify(1))]
    if profile=='full':
        from .taskflow.vendor.vivo.taskcenter import TASK_GROUPS,BIZ_PACKAGE
        plan.extend([('tasks.center','任务中心',lambda:run_groups(api,['tasks_'+key for key in TASK_GROUPS])),
          ('tasks.ec','EC浏览任务',lambda:run_groups(api,['ec_'+key for key in BIZ_PACKAGE if key!='vivop'])),('tasks.store','门店任务',lambda:run_source(api,'store_pickup_codes')),('tasks.read','社区读帖',lambda:api.community_read(3)),
          ('tasks.engage','活动帖互动',lambda:api.community_engage(30)),('tasks.weekly','周周幸运抽',lambda:(run_source(api,'weekly_tasks'),run_source(api,'weekly_codes'))),
          ('tasks.phone','话费奖励',lambda:run_source(api,'phone_rewards')),('tasks.offline','线下任务',api.offline_task_receive)])
    plan.extend([('mall.draw','商城免费抽奖',lambda:api.pm_draw(free_only=True)),('mall.subscribe','竞猜订阅',api.guess_subscribe),
      ('mall.receive','竞猜中奖领奖',lambda:run_source(api,'guess_rewards')),('mall.claim','商城免费权益及待领积分',lambda:tuple(run_source(api,key) for key in ('home_welfare','pending_points','mall_events'))),
      ('activity.lottery','抽奖活动',lambda:run_source(api,'lottery_activity_free')),('activity.appointment','预约抽奖',lambda:run_source(api,'appointment_draw')),
      ('activity.tasks','预约任务',lambda:run_source(api,'appointment_browse')),('activity.game','游戏参与及达标领奖',lambda:tuple(run_source(api,key) for key in ('game_instant_execute','game_download_execute','game_reserve_execute'))),('activity.egg','砸金蛋',lambda:run_source(api,'golden_free')),
      ('activity.double11','双11免费抽奖',lambda:run_source(api,'double11_free')),('activity.remind','双11抢券提醒',lambda:run_source(api,'coupon_reminder')),
      ('quiz.answer','积分答题（仅免费）',lambda:run_source(api,'quiz')),('quiz.gift','答题已达标奖励',lambda:run_source(api,'quiz_rewards')),
      ('quiz.lucky','夺宝幸运码',lambda:run_source(api,'crowdfunding_codes')),('member.favorite','商城收藏',api.mall_favorite),('member.wish','心愿收藏',lambda:run_source(api,'wish_favorite')),
      ('member.claim','会员中心免费权益',lambda:run_source(api,'member_benefits')),('member.applet','会员小程序免费权益',lambda:run_source(api,'member_applet_benefits')),
      ('member.xp','成长值',api.xp_info),('member.bean','金豆兑换',lambda:{'skip':'资产转换需在独立确认流程中选择，默认不自动消耗'}),('lottery.status','彩票开奖提醒',lambda:run_source(api,'powerball_subscription'))])
    if profile=='full':
        center=next(item for item in plan if item[0]=='tasks.center')
        plan=[item for item in plan if item[0]!='tasks.center']
        plan.insert(6,('tasks.discover','全量任务清单',lambda:discover_catalog(api,ALL_PKGS)))
        plan.append(('activity.dynamic','动态活动任务与免费领奖',lambda:execute_dynamic(api)))
        from .har_tasks import campaigns,membership
        plan.append(('har.activities','HAR 新增会场及免费任务',lambda:campaigns(api)))
        plan.append(('har.membership','商城新人礼包及会场免费券',lambda:membership(api)))
        plan.append(('activity.comment','预约评论抽奖资格',lambda:run_source(api,'appointment_comments')))
        plan.extend(('source.'+key,label,lambda key=key:run_source(api,key)) for key,label in SOURCE_TASKS)
        plan.append(center) # Reward/status reconciliation follows its SDK and activity dependencies.
    return [item for item in plan if not step_reason(item[0])]


def iter_events(payload):
    mode=payload.get('mode','live');raw=dict(payload['account']);aid=payload.get('account_id');profile=payload.get('profile','full')
    transport=transport_for(payload)
    account_requests_before=transport.requests_count
    current_step=None;current_label='';started=time.monotonic();requests_before=transport.requests_count
    secrets=[str(raw.get(k) or '') for k in ('vivotoken','openid','unionid')]
    try:
        app_session=None;session_version=None
        if payload.get('action','').startswith('exchange') or payload.get('action')=='app_session_check':
            from app_sessions import load
            loaded=load(mode,aid,allow_unverified=payload.get('action')=='app_session_check') if aid else None
            if loaded:
                from .app_session import account_data
                app_session,session_version=loaded;raw=account_data(app_session,raw)
                secrets.extend(c['value'] for c in app_session['cookies'] if len(c['value'])>=6)
            elif payload.get('action')=='app_session_check':raise AccountStop('未导入本账号的官网 App Cookie；应用宝微信取码不能生成官网 App 登录态')
        if not app_session and raw.get('profile_kind')=='app':raise AccountStop('该账号仅导入官网 App 登录态，请核验 Cookie 后用于商城；任务批次需要本人的小程序登录态')
        if not app_session and (payload.get('refresh_login') or not raw.get('vivotoken')):
            raw=renew(raw,transport,payload.get('allow_http_panels',False),payload.get('panel_api_key') or os.environ.get('VIVO_POOL_APIKEY',''));raw['saved_at']=time.time()
            yield {'type':'credentials','credentials':raw}
            secrets.extend(str(raw.get(k) or '') for k in ('vivotoken','openid','unionid'))
        api=make_api(raw,transport)
        if app_session:
            from .app_session import configure_api
            configure_api(api,app_session)
        api.verify_poll_count=2
        def checkpoint_done(key):
            if not aid:return False
            with db(mode) as c:
                if key=='question:wk240410b3206fb4:703318389396865152' and c.execute("SELECT 1 FROM task_checkpoints WHERE account_id=? AND day=? AND step_key IN ('v2:quiz.answer','v3:quiz.answer') AND status='completed'",(aid,today())).fetchone():return True
                return bool(c.execute("SELECT 1 FROM task_checkpoints WHERE account_id=? AND day=? AND step_key=? AND status='completed'",(aid,today(),key)).fetchone())
        def checkpoint_save(key):
            if aid:
                with db(mode) as c:c.execute('INSERT OR REPLACE INTO task_checkpoints VALUES(?,?,?,?,?,?,?,?)',(aid,today(),key,'completed','已确认领取或完成',0,0,now()))
        def checkpoint_defer(key,until):
            if aid:
                with db(mode) as c:c.execute('INSERT OR REPLACE INTO task_checkpoints VALUES(?,?,?,?,?,?,?,?)',(aid,today(),key,'deferred',json.dumps({'until':until}),0,0,now()))
        def checkpoint_deferred(key):
            if not aid:return 0
            with db(mode) as c:row=c.execute("SELECT message FROM task_checkpoints WHERE account_id=? AND step_key=? AND status='deferred' ORDER BY updated_at DESC LIMIT 1",(aid,key)).fetchone()
            try:return float(json.loads(row[0])['until']) if row else 0
            except (ValueError,KeyError,TypeError):return 0
        def bind_checkpoints(api):
            api.checkpoint_done=checkpoint_done;api.checkpoint_save=checkpoint_save
            api.checkpoint_defer=checkpoint_defer;api.checkpoint_deferred=checkpoint_deferred
        bind_checkpoints(api)
        identity={'retcode':0} if app_session else api.user_info()
        if not app_session and not api.identity_ok(identity):
            if raw.get('_pool') and not payload.get('refresh_login'):
                raw=renew(raw,transport,payload.get('allow_http_panels',False),payload.get('panel_api_key') or os.environ.get('VIVO_POOL_APIKEY',''));raw['saved_at']=time.time()
                yield {'type':'credentials','credentials':raw};api=make_api(raw,transport);identity=api.user_info()
                bind_checkpoints(api)
            if not api.ok(identity):raise AccountStop('登录态未通过平台校验，需要续期或账号验证')
        if not app_session:
            from execution_policy import verified_identity
            try:verified=verified_identity(raw,identity)
            except ValueError as error:raise AccountStop(str(error),reason_kind='identity_mismatch')
            if verified is not raw:
                raw=verified;secrets.append(str(raw['openid']))
                yield {'type':'credentials','credentials':raw}
                api=make_api(raw,transport);bind_checkpoints(api)
        if app_session:
            from .app_session import read_profile
            profile_data=read_profile(api);before=profile_data['points']
            if payload.get('action')=='app_session_check':
                yield {'type':'app_session','session_version':session_version,**profile_data}
                if profile=='app_check':
                    yield {'type':'step','step_key':'app.session.check','label':'官网 App 会话核验','status':'completed','message':f'App 登录态有效，当前 {before} 积分','elapsed_ms':int((time.monotonic()-started)*1000),'request_count':transport.requests_count-account_requests_before}
                    yield {'type':'result','points':before,'before':before,'gained':0}
                return
        else:before=api.pm_points()
        if before<0:raise AccountStop('无法读取权威积分余额，已保留账号等待重试')
        yield {'type':'balance','points':before}
        if payload.get('action')=='exchange_preview':
            from .market import current_offer
            yield {'type':'exchange_preview','points':before,'product':current_offer(api,payload['product'])};return
        if payload.get('action')=='exchange_stores':
            from .market import stores
            yield {'type':'exchange_stores','items':stores(api,payload['product'])};return
        if payload.get('action')=='exchange_order':
            from .market import order_details,fulfillment_from_order
            detail=order_details(api,payload.get('product') or {},payload['order_id'])
            yield {'type':'exchange_order','delivery':fulfillment_from_order(detail)};return
        if payload.get('action') in ('exchange_sms','exchange_captcha'):
            if payload['action']=='exchange_sms':
                from .market import mall_call
                response=mall_call(api,payload.get('product') or {},'/api/sms/send.do',{'scene':'exchange'})
                yield {'type':'verification','ok':api.ok(response),'message':response.get('message') or response.get('msg') or '', 'code':response.get('retcode',response.get('code'))}
            else:
                response=api.h5_call('https://sign.vivo.com.cn','/api/captcha/getSdkUrl.do',params={'scene':'exchange','sysCode':'vivop'},pkg='com.vivo.space')
                yield {'type':'verification','ok':api.ok(response),'sdk':response.get('data') or {}}
            return
        if payload.get('action')=='catalog':
            from .market import scopes,scope_key,read_scope
            targets=scopes(api,payload.get('catalog_scope','all'),payload.get('catalog_cities'))
            yield {'type':'catalog_plan','total':len(targets)}
            for target in targets:
                if scope_key(target) in payload.get('catalog_completed',[]):continue
                try:yield {'type':'catalog_scope','scope':target,'products':read_scope(api,target)}
                except Exception as error:yield {'type':'catalog_error','scope':target,'message':str(error)[:200]}
            return
        if payload.get('action')=='login' or profile in ('sync','login'):
            yield {'type':'step','step_key':'balance.sync','label':'同步积分','status':'completed','message':f'当前积分 {before}','elapsed_ms':int((time.monotonic()-started)*1000),'request_count':transport.requests_count-account_requests_before}
            yield {'type':'result','points':before,'before':before,'gained':0};return
        if payload.get('action')=='exchange':
            from .market import current_offer
            offer=current_offer(api,payload['product'])
            if offer['price']!=int(payload['expected_price']) or offer['stock']<=0:
                yield {'type':'exchange','status':'failed','message':'商品价格或库存已变化，请重新预检确认'};return
            product=offer['metadata'];params={k:product[k] for k in ('itemId','categoryId','channel','source','city','vkCityId') if k in product}
            category=next((row for row in api.pm_categories() if str(row.get('id'))==str(product.get('categoryId'))),None)
            if category:
                params['channel'],params['source']=('point',0) if str(category.get('channel') or 'point').lower()=='point' else ('EC',4)
            if payload.get('sms_code'):
                from .market import mall_call
                verified=mall_call(api,product,'/api/sms/verify.do',{'code':payload['sms_code'],'scene':'exchange'},method='POST')
                if not api.ok(verified):
                    yield {'type':'exchange','status':'sms_required','message':'短信验证失败'};return
            params.update(ticket=payload.get('ticket',''),constId=payload.get('const_id',''),scene='exchange' if payload.get('ticket') else '',arpuId='',cpdTaskKeyId='')
            path='/api/mall/item/exchange.do'
            if product.get('redemption_kind')=='store':
                from .market import stores
                store=str(payload.get('store_code') or '')
                if not store or store not in {row['code'] for row in stores(api,product)}:
                    yield {'type':'exchange','status':'failed','message':'请选择当前有库存的核销门店'};return
                params={'categoryId':product['categoryId'],'item':{'itemCode':product['itemId'],'itemName':product.get('name'),'itemPrice':offer['price'],'itemImage':product.get('image'),'itemType':product.get('type'),'storeVerifyWay':product.get('storeVerifyWay')},'store':{'storeCode':store},'offlineActivityKey':'','channel':product.get('channel') or 'point','source':product.get('source',0)}
                if payload.get('ticket'):params.update(ticket=payload['ticket'],constId=payload.get('const_id',''),scene='exchange')
                path='/api/mall/order/vk/doExchange.do'
            elif product.get('redemption_kind')=='cloud':path='/api/mall/cloud/exchange.do'
            else:
                params={key:params[key] for key in ('itemId','categoryId','arpuId','cpdTaskKeyId','channel','source') if key in params}
                params['categoryId']=str(params.get('categoryId',''))
                params['pts_sys_ver']='20260626_v6.1.4'
                if payload.get('ticket'):params.update(ticket=payload['ticket'],constId=payload.get('const_id',''),scene='exchange')
            yield {'type':'exchange_submit'}
            try:
                if product.get('redemption_kind') in ('store','standard'):
                    from .market import mall_call
                    response=mall_call(api,product,path,params,method='POST')
                else:response=api._pm_enc(path,params)
            except AccountStop as stop:
                if stop.provider_code in ('1050','1018'):
                    yield {'type':'exchange','status':'captcha_required' if stop.provider_code=='1050' else 'failed','message':str(stop),'provider_code':stop.provider_code};return
                raise
            code=str(response.get('retcode',response.get('code')));data=response.get('data') or {};order=str(data.get('orderId') or '')
            if code=='0':
                after=api.pm_points()
                delivery={k:data[k] for k in ('couponCode','cardNo','cardPwd','redeemCode','receiveUrl') if data.get(k)}
                if order:
                    try:
                        from .market import order_details,fulfillment_from_order
                        detail=order_details(api,product,order)
                        delivery.update(fulfillment_from_order(detail))
                        if detail.get('points') is not None:after=int(detail['points'])
                    except (Exception,StepTimeout):pass
                status='success' if order and after>=0 and before-after==offer['price'] else 'unknown'
                yield {'type':'exchange','status':status,'remote_order':order,'points_after':after if after>=0 else None,'delivery':delivery,'message':'订单和积分扣减已核对' if status=='success' else '平台已受理，订单或积分仍需核对'};return
            status='sms_required' if code=='1034' else 'captcha_required' if code in ('1050','702','703') else 'unknown' if code in ('-1','-2','None') else 'failed'
            yield {'type':'exchange','status':status,'provider_code':code,'message':str(response.get('message') or response.get('msg') or '平台未完成兑换')[:200]};return
        api.source_context=SourceContext(api,mode,aid,raw)
        plan=step_plan(api,profile)
        if payload.get('only_steps') is not None:
            from .source_bridge import _SourceAdapter
            plan.extend(('source.'+spec.key,spec.label,lambda key=spec.key:run_source(api,key)) for spec in _SourceAdapter.tasks if not spec.automatic and 'source.'+spec.key in payload['only_steps'])
            plan=[item for item in plan if item[0] in payload['only_steps'] and not step_reason(item[0])]
        for key,label,fn in plan:
            version_key=f'v{PLAN_VERSION}:{key}'
            with db(mode) as c:completed=c.execute("SELECT 1 FROM task_checkpoints WHERE account_id=? AND day=? AND step_key=? AND status='completed'",(aid,today(),version_key)).fetchone() if aid else None
            if completed and key!='tasks.discover':
                yield {'type':'step','step_key':key,'label':label,'status':'skipped','message':'该步骤已有成功断点，直接继续','elapsed_ms':0,'request_count':0};continue
            yield {'type':'step_start','step_key':key,'label':label}
            started=time.monotonic();requests_before=transport.requests_count
            retries_before=transport.retries_count;network_before=transport.network_seconds
            current_step=key;current_label=label;last_progress=[0.]
            api.partial_result=None
            def progress():
                if not payload.get('run_id') or time.monotonic()-last_progress[0]<5:return
                last_progress[0]=time.monotonic();count=transport.requests_count-requests_before
                partial=json.dumps(safe_log({'result':api.partial_result,'issues':transport.observations}),ensure_ascii=False)
                for secret in secrets:
                    if secret:partial=partial.replace(secret,'[已隐藏]')
                with db(mode) as c:c.execute("UPDATE steps SET request_count=?,elapsed_ms=?,message=?,details=? WHERE run_id=? AND step_key=? AND status='running'",(count,int((time.monotonic()-started)*1000),f'执行中 · 已发送 {count} 个请求',partial,payload['run_id'],key))
            transport.progress=progress
            transport.observations=[];value=None
            try:
                budget=int(payload.get('step_timeout_seconds',180))
                if key.startswith(('sdk.','source.browser_','source.client_tasks_')) or key in ('tasks.center','tasks.ec','activity.sweep','activity.dynamic','source.app_tasks','member.claim'):budget=max(budget,900)
                with transport.step_budget(budget):value=prune_result(fn())
                state=classify(value)
                errors=[r for r in transport.observations if r['status']=='failed']
                if errors and state in ('completed','skipped'):state='partial'
                message=json.dumps(safe_log(value),ensure_ascii=False)
            except StepTimeout as exc:state,message,value='partial',str(exc),api.partial_result
            except Exception as exc:state,message,value='failed',type(exc).__name__+'：接口步骤未完成',api.partial_result
            detail_text=json.dumps(safe_log({'result':value,'issues':transport.observations,'metrics':{'retries':transport.retries_count-retries_before,'network_ms':int((transport.network_seconds-network_before)*1000)}}),ensure_ascii=False)
            for secret in secrets:
                if secret:message=message.replace(secret,'[已隐藏]');detail_text=detail_text.replace(secret,'[已隐藏]')
            details=json.loads(detail_text)
            # Full results are stored separately; the summary never contains a broken JSON fragment.
            if len(message)>1200:
                summary={k:v for k,v in (value or {}).items() if not isinstance(v,(list,dict))} if isinstance(value,dict) else {'items':len(value) if isinstance(value,(list,tuple)) else 0}
                message=json.dumps(safe_log(summary),ensure_ascii=False)+' · 完整结果见逐项明细'
            if transport.observations:message+=f' · 接口异常/不可用 {len(transport.observations)} 项，详见明细'
            elapsed=int((time.monotonic()-started)*1000);count=transport.requests_count-requests_before
            if aid and state=='completed':
                with db(mode) as c:c.execute('INSERT OR REPLACE INTO task_checkpoints VALUES(?,?,?,?,?,?,?,?)',(aid,today(),version_key,state,message,elapsed,count,now()))
            yield {'type':'step','step_key':key,'label':label,'status':state,'message':message,'details':details,'elapsed_ms':elapsed,'request_count':count}
            current_step=None;transport.progress=None
        after=api.pm_points()
        if after<0:raise AccountStop('步骤已处理，最终积分核对失败，保留断点等待同步')
        yield {'type':'result','points':after,'before':before,'gained':after-before}
    except AccountStop as exc:
        diagnostics=safe_log(getattr(exc,'diagnostics',{}))
        if current_step:
            yield {'type':'step','step_key':current_step,'label':current_label,'status':'failed','message':str(exc),'elapsed_ms':int((time.monotonic()-started)*1000),'request_count':transport.requests_count-requests_before,'details':safe_log({'result':getattr(api,'partial_result',None),'issues':transport.observations,'stop':{'provider_code':exc.provider_code,**diagnostics}})}
        network=getattr(exc,'network_failure',False)
        yield {'type':'error','message':str(exc),'network_failure':network,'provider_code':exc.provider_code,'diagnostics':diagnostics,'retryable':'执行租约' in str(exc) or network and not transport.unsafe_sent}
    except Exception as exc:
        yield {'type':'error','message':type(exc).__name__+'：内置协议执行失败'}
