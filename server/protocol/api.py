"""Built-in HTTP API methods, extracted from the user-provided protocol client. No CLI runner."""
from __future__ import annotations
from .common import ALL_PKGS, BBS, BIZ_PACKAGE, EDEN, FORUM_SIG_KEY, GAP, H5_ORIGIN, H5_REFERER, MAIN_SIGN_PKG, MEMBER, MPC, MSHOPACT, MaodunCipher, NET_PREFIX, PN_MAP, POINTACT, POINTH5, POINTSDK, POINTWAP, SCRM_ORIGIN, SHOP_FBAPI, SIGNHOST, SIGN_VERSION, TOKEN_REUSE_SECONDS, UA_SPACE, VIVO_APPID, WUKONGAPI, WX_APPID, _LOG_TLS, _SOCKS_OK_CACHE, _luhn, _px, _socks_ok, _url_values, _utf8_only, _wave_net, gen_imei, gen_oaid, get_sign, log, m_value_for_post, now_ms, now_ts
import hashlib
import hmac
import json
import os
import random
import re
import struct
import threading
import time
import uuid
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
import requests

class Account:

    def __init__(self, raw: Dict[str, str]):
        from .devices import resolve_device
        self.device=resolve_device(raw)
        self.openid = raw['openid']
        self.vivotoken = raw['vivotoken']
        self.unionid = raw.get('unionid', '')
        self.phone = raw.get('phone', '')
        self.city = raw.get('city') or ''
        self.vk_city_id = raw.get('vkCityId') or ''
        self.imei = self.device.get('imei') or gen_imei(self.openid)
        self.oaid = self.device.get('oaid') or gen_oaid(self.openid)
        self.device.update(imei=self.imei,oaid=self.oaid)
        nick = raw.get('_wx_nick') or ''
        base = f'{self.openid[:8]}…{self.openid[-4:]}'
        self.label = f'{nick}({self.phone})' if nick else base + (f'({self.phone})' if self.phone else '')

    def mask_token(self) -> str:
        t = self.vivotoken
        return t[:6] + '…' + t[-4:] if len(t) > 12 else t

class VivoApi:
    """一个账号一个实例；统一封装所有可完成任务。"""

    def __init__(self, acct: Account, proxy: Optional[Dict[str, str]]=None):
        self.acct = acct
        from .devices import webview_ua,wap_ua
        self.ua_h5=webview_ua(acct.device)
        self.ua_wap=wap_ua(acct.device)
        self.ua_space=UA_SPACE+' '+self.ua_h5
        self.s = requests.Session()
        self.proxy = _px(proxy)
        if self.proxy:
            self.s.proxies.update(self.proxy)
        self._last = 0.0
        self._install_cookies()

    def _install_cookies(self) -> None:
        a = self.acct
        dom = '.vivo.com.cn'
        for k, v in (('vvc_imei', a.imei), ('vvc_oaid', a.oaid), ('vvc_openid', a.openid), ('vvc_r', a.vivotoken), ('vivo_account_cookie_iqoo_openid', a.openid), ('vivo_account_cookie_iqoo_vivotoken', a.vivotoken)):
            self.s.cookies.set(k, v, domain=dom)

    def _gap(self) -> None:
        d = time.time() - self._last
        if d < GAP:
            time.sleep(GAP - d)
        self._last = time.time()

    def cookie_header(self, pkg: Optional[str]='') -> str:
        if getattr(self,'app_session',None):
            from .app_session import cookie_header
            return cookie_header(self.app_session)
        a = self.acct
        parts = [f'vvc_openid={a.openid}', f'vvc_r={a.vivotoken}',f'vivo_account_cookie_iqoo_openid={a.openid}',f'vivo_account_cookie_iqoo_vivotoken={a.vivotoken}']
        if pkg:
            parts.append(f'vvc_pn={pkg}')
        parts.append(f'vvc_imei={a.imei}')
        return ';'.join(parts)

    def _h5_headers(self, pkg: Optional[str]='', extra: Optional[Dict[str, str]]=None) -> Dict[str, str]:
        h = {'User-Agent': self.ua_h5, 'Referer': H5_REFERER, 'Origin': H5_ORIGIN, 'Accept': 'application/json, text/plain, */*', 'cookie': self.cookie_header(pkg)}
        if extra:
            h.update(extra)
        return h

    def h5_call(self, host: str, path: str, *, method: str='GET', params: Optional[Dict[str, Any]]=None, pkg: Optional[str]='com.vivo.space', extra_cookie: str='', timeout: int=20) -> Dict[str, Any]:
        """任务族通用调用（pointh5 / sign / pointsdk / pointwap）。"""
        self._gap()
        url = host.rstrip('/') + path
        url += ('&' if '?' in url else '?') + f't={now_ms()}'
        ck = self.cookie_header(pkg) + (';' + extra_cookie if extra_cookie else '')
        h = {'User-Agent': self.ua_h5, 'Referer': H5_REFERER, 'Origin': H5_ORIGIN, 'Accept': 'application/json, text/plain, */*', 'cookie': ck}
        payload = {k: v for k, v in (params or {}).items() if v is not None}
        try:
            if method.upper() == 'GET':
                r = self.s.get(url, params=payload, headers=h, timeout=timeout)
            else:
                r = self.s.post(url, json=payload, headers={**h, 'content-type': 'application/json'}, timeout=timeout)
            response=r.json()
            return response if isinstance(response,dict) else {'_err':'接口未返回有效 JSON 对象','response_type':type(response).__name__}
        except Exception as e:
            return {'_err': str(e)[:120]}

    @staticmethod
    def ok(res: Any) -> bool:
        if not isinstance(res, dict):
            return False
        if 'retcode' in res:
            try:
                return int(res['retcode']) == 0
            except (TypeError, ValueError):
                return False
        try:
            return int(res.get('code', -1)) in (0, 200)
        except (TypeError, ValueError):
            return False

    @staticmethod
    def sign_ok(res: Any) -> bool:
        """签到达成态：0/200 成功、10002/10003 已签。"""
        if not isinstance(res, dict):
            return False
        return str(res.get('code', res.get('retcode'))) in ('0', '200', '10002', '10003')

    @staticmethod
    def identity_ok(res: Any) -> bool:
        """登录态校验。31140003 = MPC 小程序网关不适用，上游参考实现视其为正常
        （passport 会话正常，任务后端以 task/list 为准），不作为登录失败。"""
        if not isinstance(res, dict):
            return False
        code = res.get('retcode', res.get('code'))
        return VivoApi.ok(res) or str(code) == '31140003'

    def user_info(self) -> Dict[str, Any]:
        self._gap()
        h = {'content-type': 'application/json;charset=UTF-8', 'wxAppId': WX_APPID, 'vivo-token': self.acct.vivotoken}
        try:
            r = self.s.post(MPC + '/api/wx/user/userInfo', headers=h, timeout=20)
            return r.json()
        except Exception as e:
            return {'_err': str(e)[:120]}

    def sign_biz_list(self, pkg: str='com.vivo.space') -> List[Dict[str, Any]]:
        r = self.h5_call(POINTH5, '/api/mall/task/center/new/signBizList.do', params={'noToast': '1'}, pkg=pkg)
        d = r.get('data')
        return d if isinstance(d, list) else []

    def sign_do(self, sys_code: str, pkg: Optional[str]='_auto_') -> Dict[str, Any]:
        """POST sign.vivo.com.cn/api/sign/dosign.do（sysCode + vvc_pn 成对）。"""
        if pkg == '_auto_':
            pkg = BIZ_PACKAGE.get(sys_code, '')
        return self.h5_call(SIGNHOST, '/api/sign/dosign.do', method='POST', params={'sysCode': sys_code}, pkg=pkg or '')

    def sign_all(self) -> List[Dict[str, Any]]:
        """11 业务端签到（动作后重读 signBizList 复核，避免响应解析失败误判）。"""
        out = []
        for b in self.sign_biz_list():
            biz, pkg, name = (b.get('bizCode'), b.get('packageName'), b.get('bizName'))
            if str(b.get('isSign')) == '1':
                out.append({'biz': biz, 'name': name, 'res': 'already'})
                continue
            r = self.sign_do(biz, pkg=pkg or '')
            out.append({'biz': biz, 'name': name, 'res': 'ok' if self.sign_ok(r) else r.get('msg') or r.get('code'), 'code': r.get('code')})
        try:
            after = {b.get('bizCode'): str(b.get('isSign')) for b in self.sign_biz_list()}
            for x in out:
                if after.get(x.get('biz')) == '1':
                    x['after_signed'] = True
        except Exception:
            pass
        return out

    def sign_main(self) -> Dict[str, Any]:
        """vivo+ SPA 主签到"""
        home = self.h5_call(POINTH5, '/api/sign/home.do', pkg=MAIN_SIGN_PKG)
        d = home.get('data') or {}
        if str(d.get('hasSigned')) in ('1', 'True', 'true'):
            return {'action': 'already', 'hasSigned': d.get('hasSigned')}
        r = self.h5_call(POINTH5, '/api/sign/start.do', method='POST', params={'taskId': d.get('taskId')}, pkg=MAIN_SIGN_PKG)
        code = r.get('retcode', r.get('code'))
        return {'action': 'signed' if str(code) == '0' else 'already' if str(code) == '10002' else 'failed', 'code': code}

    def sign_notify(self, on: int=1) -> Dict[str, Any]:
        return self.h5_call(SIGNHOST, '/api/sign/notify/notify.do', method='POST', params={'notifyFlag': int(on)}, pkg=MAIN_SIGN_PKG)

    def _tasks_for_pkg(self, pkg: str) -> Dict[Any, Dict[str, Any]]:
        out: Dict[Any, Dict[str, Any]] = {}
        for t in range(0, 7):
            r = self.h5_call(POINTH5, '/api/task/listByType.do', params={'type': str(t)}, pkg=pkg)
            if str(r.get('retcode')) != '0':
                continue
            d = r.get('data')
            items = d if isinstance(d, list) else (d or {}).get('list') or (d or {}).get('tasks') or []
            for x in items:
                if isinstance(x, dict) and x.get('id') is not None:
                    x = dict(x)
                    x['_pkg'] = pkg
                    out[x['id']] = x
        return out

    def sign_biz_names(self) -> Dict[str, str]:
        return {b.get('bizName'): b.get('bizCode') for b in self.sign_biz_list() if b.get('bizName')}

    def _biz_for_name(self, name: str, mapping: Dict[str, str]) -> Optional[str]:
        for bn, biz in mapping.items():
            if bn and bn in str(name):
                return biz
        return 'vivop' if 'vivo+' in str(name) else None

    def receive_point(self, task: Dict[str, Any]) -> Dict[str, Any]:
        p = {'taskId': task.get('id')}
        for k in ('type', 'subType', 'taskSource'):
            if task.get(k) is not None:
                p[k] = task[k]
        return self.h5_call(POINTH5, '/api/task/receivePoint.do', method='POST', params=p,pkg=task.get('_pkg') or MAIN_SIGN_PKG)

    def ec_receive_point(self, task: Dict[str, Any]) -> Dict[str, Any]:
        p = {'noLoading': True, 'from': 'EC', 'taskId': task.get('id'), 'businessCode': task.get('businessCode') or 'vivop'}
        for k in ('taskSource', 'type', 'subType'):
            if task.get(k) is not None:
                p[k] = task[k]
        return self.h5_call(POINTH5, '/api/task/ec/receivePoint.do', method='POST', params=p,pkg=task.get('_pkg') or MAIN_SIGN_PKG)

    def task_wish(self, tid: Any, pkg='com.vivo.space') -> Dict[str, Any]:
        return self.h5_call(POINTSDK, '/web/task/wish', method='POST', params={'taskId': tid, 'noLoading': True, 'noToast': True},pkg=pkg)

    def complete_web_task(self, key_id: Any, pkg='com.vivo.space') -> Dict[str, Any]:
        return self.h5_call(POINTH5, '/api/task/completeWebTask.do', method='POST', params={'taskKeyId': str(key_id)},pkg=pkg)

    def vivop_complete(self, key_id: Any, sub_key_id=None, business_code='vivop') -> Dict[str, Any]:
        return self.h5_call(POINTH5, '/api/task/vivop/complete.do', method='POST', params={'keyId': key_id, 'subKeyId':sub_key_id,'businessCode': business_code})

    def community_auth(self):
        if not hasattr(self,'_community_auth_result'):
            self._community_auth_result=self._community_post('/api/community/client/auth/auth',{})
        return self._community_auth_result

    def _community_body(self) -> Dict[str, str]:
        ts = str(now_ms())
        nonce = hashlib.md5((self.acct.imei + ts + str(random.randint(0, 999))).encode()).hexdigest()
        return {'sig': get_sign(sorted([ts, nonce, 'j56Hi8o1xzu6Gp'])), 'timestamp': ts, 'nonce': nonce}

    def _community_post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        self._gap()
        b = self._community_body()
        b.update(body)
        try:
            r = self.s.post(BBS + path, data=json.dumps(b, ensure_ascii=False).encode(), headers={'User-Agent': self.ua_space, 'Content-Type': 'application/json;charset=utf-8'}, timeout=20)
            return r.json()
        except Exception as e:
            return {'_err': str(e)[:120]}

    def community_hot_threads(self, limit: int=8) -> List[str]:
        if hasattr(self,'_community_threads'):return self._community_threads[:limit]
        tids: List[str] = []

        def grab(blob: str) -> None:
            for a, b in re.findall('(?:/newbbs/thread/|/thread/)(\\d+)|[?&]tid=(\\d+)', str(blob)):
                tids.append(a or b)
        for pn in (1, 2, 3):
            r = self._eden_post('client/bbk/activity/index', {'pageNum': str(pn), 'cfrom': '652'})
            acts = (r.get('value') or {}).get('activities') or []
            if not acts:
                break
            for a in acts:
                grab(str(a.get('url') or '') + str(a.get('cardActivity') or ''))
        if not tids:
            try:
                r2 = self.s.get(BBS + '/recommend/homeRecommend', headers={'User-Agent': self.ua_h5}, timeout=15)
                try:
                    for s in (r2.json().get('data') or {}).get('recommendSections') or []:
                        if s.get('tid') is not None:
                            tids.append(str(s['tid']))
                except Exception:
                    tids = [a or b for a, b in re.findall('(?:/thread/(\\d+)|tid=(\\d+))', r2.text)]
            except Exception:
                pass
        seen, out = (set(), [])
        for t in tids:
            if t not in seen:
                seen.add(t)
                out.append(t)
        self._community_threads=out
        return out[:limit]

    def community_read(self, count: int=3) -> Dict[str, Any]:
        auth=self.community_auth()
        if not self.ok(auth):return {'ok':False,'reason':'社区授权未通过','response':auth}
        tids = self.community_hot_threads(limit=max(count, 5))
        if not tids:
            return {'ok': False, 'msg': '无帖子 id（不编造）'}
        read = []
        for tid in tids[:count]:
            r = self._community_post('/api/community/client/thread/detail', {'tid': str(tid)})
            read.append({'tid': tid, 'code': r.get('code')})
            time.sleep(0.8)
        return {'ok': True, 'read': read}

    def community_engage(self, limit: int=30) -> Dict[str, Any]:
        """活动帖协议侧参与：点赞 + 收藏 + 阅读计数 """
        auth=self.community_auth()
        if not self.ok(auth):return {'ok':False,'reason':'社区授权未通过','response':auth}
        tids = self.community_hot_threads(limit=limit)
        okc = ('0', '16002', '16016')
        res = []
        for tid in tids:
            rec = {'tid': tid}
            for act, path, extra in (('like', '/api/community/client/thread/like', {'type': 1}), ('favorite', '/api/community/client/thread/favorite', {'type': 1}), ('read', '/api/community/client/thread/incrReadNum', {})):
                body = {'tid': str(tid)}
                body.update(extra)
                r = self._community_post(path, body)
                rec[act] = {'code':r.get('code'),'msg':r.get('msg'),'status':'completed' if str(r.get('code')) in okc else 'failed'}
            res.append(rec)
            time.sleep(0.5)
        return {'total': len(res), 'results': res}

    def complete_task(self, t: Dict[str, Any], mapping: Dict[str, str]) -> Dict[str, Any]:
        from .tasks import perform_task
        return perform_task(self,t,mapping)

    def complete_all_tasks(self, pkgs: List[str]) -> Dict[str, Any]:
        mapping = self.sign_biz_names()
        tally: Dict[str, int] = {}
        for pkg in pkgs:
            for _tid, t in self._tasks_for_pkg(pkg).items():
                r = self.complete_task(t, mapping)
                tally[r['result']] = tally.get(r['result'], 0) + 1
        return tally

    def sdk_report_all(self, count: int=5) -> Dict[str, Any]:
        total = 0
        uploaded = 0
        for pkg in dict.fromkeys(ALL_PKGS):
            cfg = self.h5_call(POINTSDK, '/sdk/config/action/list', method='POST', params={'pkgName': pkg})
            acts = (cfg.get('data') or {}).get('actions') or []
            for a in acts:
                aid = a.get('actionId')
                if not aid:
                    continue
                total += 1
                up = self.h5_call(POINTSDK, '/sdk/action/upload', method='POST', params={'openid': self.acct.openid, 'token': self.acct.vivotoken, 'pkgName': pkg, 'actionId': aid, 'count': str(count), 'notifyPattern': '1'})
                if self.ok(up):
                    uploaded += 1
                self.h5_call(POINTSDK, '/sdk/task/receive/point', method='POST', params={'openid': self.acct.openid, 'token': self.acct.vivotoken, 'pkgName': pkg, 'actionId': aid, 'notifyPattern': '1'})
        return {'actions': total, 'uploaded': uploaded}

    def _pm_headers(self, json_body: bool=False) -> Dict[str, str]:
        h = {'User-Agent': self.ua_h5, 'Referer': POINTH5 + '/', 'Origin': POINTH5}
        if getattr(self,'app_session',None):h['Cookie']=self.cookie_header()
        if json_body:
            h['Content-Type'] = 'application/json'
        return h

    def _pm_get(self, path: str, **params) -> Dict[str, Any]:
        self._gap()
        params.setdefault('noToast', 1)
        params.setdefault('pts_sys_ver','20261013_v6.1.7')
        params.setdefault('pts_sys_t',now_ms())
        try:
            return self.s.get(POINTH5 + path, params=params, headers=self._pm_headers(), timeout=25).json()
        except Exception:
            return {}

    def _pm_post(self, path: str, **params) -> Dict[str, Any]:
        self._gap()
        params.pop('noToast', None)
        try:
            return self.s.post(POINTH5 + path, params={'pts_sys_t': now_ms()}, json=params, headers=self._pm_headers(True), timeout=25).json()
        except Exception:
            return {}

    def _pm_enc(self, path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        try:
            c = MaodunCipher()
        except Exception as e:
            return {'retcode': -2, 'message': '缺 pycryptodome，跳过加密接口：' + str(e)[:60]}
        self._gap()
        body = {'jvq_param': c.encrypt(params), 'pts_sys_ver': '20261013_v6.1.7'}
        try:
            d = self.s.post(POINTH5 + path, params={'pts_sys_t': now_ms()}, json=body, headers=self._pm_headers(True), timeout=25).json()
        except Exception as e:
            return {'retcode': -1, 'message': str(e)[:120]}
        if isinstance(d, dict) and d.get('jvq_response'):
            try:
                return json.loads(c.decrypt(d['jvq_response']))
            except Exception as e:
                return {'retcode': -1, 'message': 'decrypt:' + str(e)[:80]}
        return d if isinstance(d, dict) else {}

    def pm_points(self) -> int:
        """积分（多源交叉，避免单接口限流时误报 0）。

        来源顺序：① `pointh5 header.do` ② `mpc userInfo` ③ `sign capital/pointInfo`
        任一成功即返回；全失败返回 -1（表示"取不到"而非 0 分）。
        """
        try:
            response=self._pm_get('/api/mall/v5/home/header.do')
            d = response.get('data') or {} if self.ok(response) else {}
            if d.get('points') is not None:
                return int(d['points'])
        except Exception:
            pass
        try:
            r = self.s.post(MPC + '/api/wx/user/userInfo', headers={'content-type': 'application/json;charset=UTF-8', 'vivo-token': self.acct.vivotoken, 'wxAppId': VIVO_APPID}, timeout=15, proxies=self.proxy)
            response=r.json()
            d2 = response.get('data') or {} if self.ok(response) else {}
            if d2.get('points') is not None:
                return int(d2['points'])
        except Exception:
            pass
        try:
            response=self.h5_call(SIGNHOST, '/api/sign/capital/pointInfo.do', pkg=MAIN_SIGN_PKG)
            d3 = response.get('data') or {} if self.ok(response) else {}
            for k in ('point', 'points', 'pointQuantity', 'capitalPoint'):
                if d3.get(k) is not None:
                    return int(d3[k])
        except Exception:
            pass
        return -1

    def pm_categories(self) -> List[Dict[str, Any]]:
        out = (self._pm_get('/api/mall/v5/home/categories.do').get('data') or {}).get('categories') or []
        ec = (self._pm_get('/api/mall/v5/ec/categories.do').get('data') or {}).get('categories') or []
        seen, merged = (set(), [])
        for c in list(out) + list(ec):
            if c.get('id') not in seen:
                seen.add(c['id'])
                merged.append(c)
        return merged

    def pm_items(self, cid: int) -> List[Dict[str, Any]]:
        return (self._pm_get('/api/mall/v5/home/items.do', categoryId=cid).get('data') or {}).get('items') or []

    def pm_draw(self, free_only: bool=False) -> Dict[str, Any]:
        """商城抽奖。

        :param free_only: True = **只抽免费场次**（price==0），一分不花——
                          `VIVO_SPEND_MODE=earn`（默认）时的形态；
                          False = 旧行为（budget 内的付费场也抽）。
        """
        budget = max(0, self.pm_points())
        results = []
        for cat in self.pm_categories():
            cid = cat.get('id')
            ch = str(cat.get('channel') or 'point').lower()
            ch2, src = ('point', 0) if ch == 'point' else ('EC', 4)
            for it in self.pm_items(cid):
                if it.get('playMethod') != 1:
                    continue
                price = it.get('finalPoints')
                if price is None:
                    price = it.get('price')
                if price is None or price > budget:
                    continue
                if free_only and int(price or 0) > 0:
                    continue
                store = it.get('availStock')
                if store is not None and store <= 0:
                    continue
                r = self._pm_enc('/api/mall/item/draw.do', {'itemId': it.get('id'), 'categoryId': cid, 'acceptError': True, 'noLoading': True, 'scene': '', 'ticket': '', 'constId': '', 'channel': ch2, 'source': src})
                won = bool(isinstance(r.get('data'), dict) and (r['data'].get('orderId') or r['data'].get('compensateGift')))
                results.append({'itemId': it.get('id'), 'name': it.get('name'), 'retcode': r.get('retcode'), 'won': won})
                budget -= int(price or 0)
                if budget <= 0:
                    break
        return {'pointsBefore': budget, 'results': results, 'pointsAfter': self.pm_points()}

    def pm_guess(self) -> Dict[str, Any]:
        ga = (self._pm_get('/api/nmall/home/explicit/list.do').get('data') or {}).get('guessActivity') or {}
        if not ga.get('id'):
            return {'skip': '无竞猜活动'}
        if ga.get('isChipIn') or (ga.get('currentTimes') or 0) >= (ga.get('limitTimes') or 0):
            return {'skip': '本期已下注'}
        opts = ga.get('options') or []
        if not opts:
            return {'skip': '无选项'}
        r = self._pm_post('/api/activity/guess/chipIn.do', activityId=ga['id'], points=ga.get('minChip') or 5, optionCode=opts[0].get('code'), scene='', ticket='', constId='')
        return {'activity': ga.get('name'), 'resp': r.get('retcode')}

    def pm_events(self) -> Dict[str, Any]:
        """活动任务领奖"""
        evs = (self._pm_get('/api/mall/task/center/head.do').get('data') or {}).get('mallEvens') or []
        done = []
        for e in evs:
            key = e.get('eventKey')
            if not key:
                continue
            r = self._pm_post('/api/mall/event/receive.do', eventKey=key, _t=now_ms())
            done.append({'name': e.get('name'), 'retcode': r.get('retcode'), 'got': (r.get('data') or {}).get('receivePoint')})
        return {'total': len(evs), 'results': done}

    def pm_claim(self) -> Dict[str, Any]:
        """首页福利 + 未到账积分 + 待领积分。"""
        out: Dict[str, Any] = {}
        wf = (self._pm_get('/api/mall/v5/home/dynamic.do').get('data') or {}).get('welfare') or {}
        if wf.get('id'):
            out['welfare'] = self._pm_post('/api/mall/v5/home/receiveWelfare.do', welfareId=wf['id']).get('retcode')
        up = self._pm_get('/api/task/unrecvPoint.do').get('data') or {}
        if up.get('unrecvPoint'):
            out['tz_grant'] = self._pm_post('/api/mall/tz/grant.do').get('retcode')
        return out

    def lottery_all(self) -> Dict[str, Any]:
        acts = (self.h5_call(POINTH5, '/api/lottery/list.do', params={}).get('data') or {}).get('activities') or []
        now = now_ms()
        n = 0;results=[]
        for a in acts:
            if not int(a.get('endTime') or 0) > now >= int(a.get('startTime') or 0):
                continue
            aid = a.get('id')
            det = self.h5_call(POINTH5, '/api/lottery/detail.do', params={'actId': aid}).get('data') or {}
            st = self.h5_call(POINTH5, '/api/lottery/userStats.do', params={'actId': aid}).get('data') or {} if det.get('login') else {}
            free=next((int(st[k] or 0) for k in ('freeTimes','freeCount','freeAvaCnt','freeDrawCount') if k in st),0)
            if not free:
                results.append({'id':aid,'name':a.get('name'),'status':'skipped','reason':'平台未提供可用的免费次数，不自动消耗积分'});continue
            args = {k: det.get(k) or st.get(k) for k in ('scene', 'ticket', 'constId')}
            if any((v is None for v in args.values())):
                continue
            for _ in range(free):
                r = self.h5_call(POINTH5, '/api/lottery/draw.do', method='POST', params={'actId': aid, **args})
                success=self.ok(r)
                results.append({'id':aid,'name':a.get('name'),'status':'completed' if success else 'failed','retcode':r.get('retcode'),'message':r.get('message') or r.get('msg')})
                if success:n+=1
                else:break
        return {'drawn': n,'results':results}

    def game_tasks(self) -> Dict[str, Any]:
        """游戏任务：列表 → 对每个玩法（秒开0/下载1/预约2）行为上报 upload → 领奖 getReward。

        源码（chunk17/30）：`gameUpload({pkgName, stat, cookie:imei, token, playMethod})`
        * stat=3 客户端跳转回跳后触发（本协议发 stat=4 完整参与）；
        * `getRewardStatus({pkgName, gameCfgId})` 返回 status==1 即可领。
        """
        rewarded = 0
        uploaded = 0
        for pm in (0, 1, 2):
            r = self.h5_call(POINTH5, '/api/gameact/gameList.do', method='POST', params={'playMethod': pm})
            for g in (r.get('data') or {}).get('games') or []:
                key = {0: 'openReward', 1: 'downloadReward', 2: 'appointmentReward'}.get(pm)
                rw = g.get(key) or {} if key else {}
                tok = g.get('token')
                pkg = g.get('pkgName')
                gid = g.get('id')
                if tok and pkg:
                    up = self.h5_call(POINTH5, '/api/gameact/upload.do', method='POST', params={'noLoading': True, 'pkgName': pkg, 'stat': 4, 'cookie': self.acct.imei, 'token': tok, 'playMethod': pm})
                    if str(up.get('retcode')) == '0':
                        uploaded += 1
                self.h5_call(POINTH5, '/api/gameact/refreshRewardStat.do', params={'gameCfgId': gid})
                st = self.h5_call(POINTH5, '/api/gameact/getRewardStatus.do', params={'pkgName': pkg, 'gameCfgId': gid})
                if str((st.get('data') or {}).get('status')) != '1' and str(rw.get('status')) != '1':
                    continue
                rr = self.h5_call(POINTH5, '/api/gameact/getReward.do', method='POST', params={'noLoading': True, 'gameCfgId': gid, 'token': tok, 'pkgName': pkg, 'objective': rw.get('objective'), 'cookie': self.acct.imei, 'scene': g.get('scene'), 'ticket': g.get('ticket'), 'constId': g.get('constId')})
                if str(rr.get('retcode')) == '0':
                    rewarded += 1
        return {'uploaded': uploaded, 'rewarded': rewarded}

    def _wk(self, path: str, *, method: str='GET', body: Optional[Dict[str, Any]]=None, params: Optional[Dict[str, Any]]=None) -> Dict[str, Any]:
        """wukongapi 调用（不带 Origin，wukongapi 对跨域 Origin 返回空）。"""
        self._gap()
        h = {'User-Agent': self.ua_space, 'Referer': H5_REFERER}
        url = WUKONGAPI + path
        try:
            if method.upper() == 'GET':
                (params or {}).setdefault('t', now_ms())
                return self.s.get(url, params=params, headers=h, timeout=25).json()
            h['Content-Type'] = 'application/json'
            return self.s.post(url, params={'t': now_ms()}, json=body or {}, headers=h, timeout=25).json()
        except Exception as e:
            return {'_err': str(e)[:120]}
    WEEKLY_SITE = 'wk261008324ff1c9'

    def _wk_cookie(self) -> str:
        a = self.acct
        return 'vivo_account_cookie_iqoo_openid=' + a.openid + ';vivo_account_cookie_iqoo_vivotoken=' + a.vivotoken + ';vivo_account_cookie_iqoo_authtoken=' + a.vivotoken + ';vivo_account_cookie_iqoo_checksum=' + a.vivotoken + ';vivo_account_cookie_iqoo_regioncode=CN' + ';vivo_account_cookie_wechat_from=108;app_package=minip.vivop'

    def _wkapc(self, path: str, *, method: str='GET', params=None, body=None) -> Dict[str, Any]:
        """wukongapc（SCRM 活动后端）通用调用。"""
        self._gap()
        h = {'User-Agent': self.ua_h5, 'Origin': SCRM_ORIGIN, 'Referer': SCRM_ORIGIN + '/', 'Accept': 'application/json, text/plain, */*', 'cookie': self._wk_cookie()}
        url = WUKONGAPI + path + ('&' if '?' in path else '?') + 't=' + str(now_ms())
        try:
            if method.upper() == 'GET':
                return self.s.get(url, params=params or {}, headers=h, timeout=25).json()
            h['Content-Type'] = 'application/json;charset=UTF-8'
            return self.s.post(url, json=body or {}, headers=h, timeout=25).json()
        except Exception as e:
            return {'_err': str(e)[:120]}

    def weekly_tasks(self, activity_id: str='1033567662615038848') -> List[Dict[str, Any]]:
        """周周抽奖任务列表。"""
        r = self._wkapc('/wukongapc/task/list', params={'activityId': activity_id, 'serialNumber': '', 'siteId': self.WEEKLY_SITE})
        return (r.get('data') or {}).get('taskList') or [] if str(r.get('code')) == '0' else []

    def weekly_finish_all(self, activity_id: str='1033567662615038848') -> Dict[str, Any]:
        """完成全部可协议达成的任务（浏览类 task/finish + 远程类 remote/finish），攒抽奖码。"""
        self._wkapc('/wukongapc/task/remote/finish', params={'activityId': activity_id, 'locationAuthorizedDTO': '{"hasUserLocation":false,"province":"","city":""}', 'siteId': self.WEEKLY_SITE})
        done, failed = ([], [])
        for t in self.weekly_tasks(activity_id):
            if int(t.get('taskStatus') or 0) == 1:
                continue
            if t.get('isRemoteTask'):
                continue
            tid = t.get('taskId')
            r = self._wkapc('/wukongapc/task/finish', method='POST', body={'activityId': activity_id, 'taskId': tid, 'appPkg': '', 'locationAuthorizedDTO': {'hasUserLocation': False, 'province': '', 'city': ''}, 'siteId': self.WEEKLY_SITE})
            if str(r.get('code')) == '0':
                done.append(t.get('taskName'))
            else:
                failed.append({t.get('taskName'): str(r.get('msg'))[:40]})
        return {'finished': done, 'failed': failed}

    def weekly_exchange(self, activity_id: str='1033567662615038848') -> Dict[str, Any]:
        """把全部可用抽奖次数兑换成幸运码。"""
        r = self._wkapc('/wukongapc/carveupLuck/lucky/available', params={'activityId': activity_id, 'siteId': self.WEEKLY_SITE})
        av = int((r.get('data') or {}).get('availableCount') or 0)
        if av <= 0:
            return {'availableCount': av, 'luckyNoAmount': (r.get('data') or {}).get('luckyNoAmount')}
        r2 = self._wkapc('/wukongapc/carveupLuck/lucky/exchange', method='POST', body={'hasUserLocation': False, 'province': '', 'city': '', 'activityId': activity_id, 'count': av, 'siteId': self.WEEKLY_SITE})
        codes = r2.get('data') if isinstance(r2.get('data'), list) else []
        return {'exchanged': len(codes), 'luckyCodes': codes, 'err': None if str(r2.get('code')) == '0' else r2.get('msg')}

    def weekly_lottery(self) -> Dict[str, Any]:
        """周周幸运抽全流程：任务全做 → 次数全兑幸运码。"""
        fin = self.weekly_finish_all()
        ex = self.weekly_exchange()
        return {'tasks': fin, 'exchange': ex}

    def golden_egg(self) -> Dict[str, Any]:
        """砸金蛋（每日免费 1 次）。"""
        aid, site = ('1024744348656337152', 'wk241209756168f3')
        av = self._wk('/wukongapc/lottery/user/available/query', params={'activityId': aid, 'siteId': site}).get('data') or {}
        if int(av.get('freeAvaCnt') or 0) <= 0:
            return {'skip': '无免费次数'}
        r = self._wk('/wukongapc/lottery/draw', method='POST', body={'activityId': aid, 'topicId': site, 'siteId': site, 'extend': {'hostUrl': H5_REFERER + '&h5JumpBackFlag=1', 'locationAuthorizedDTO': {'hasUserLocation': False, 'province': '', 'city': ''}}})
        return {'code': r.get('code'), 'reward': (r.get('data') or {}).get('rewardName')}

    def double11(self) -> Dict[str, Any]:
        """26年双11会员会场预热抽奖（每日免费 2 次）。"""
        aid, site = ('1030298797554535360', 'wk2609233beab7e8')
        drew, total = (0, 0)
        for _ in range(5):
            av = self._wk('/wukongapc/lottery/user/available/query', params={'activityId': aid, 'groupId': 1}).get('data') or {}
            if int(av.get('freeAvaCnt') or 0) <= 0:
                break
            r = self._wk('/wukongapc/lottery/draw', method='POST', body={'activityId': aid, 'topicId': site, 'siteId': site, 'extend': {'hostUrl': H5_REFERER + '&h5JumpBackFlag=1', 'locationAuthorizedDTO': {'hasUserLocation': False, 'province': '', 'city': ''}}})
            name = str((r.get('data') or {}).get('rewardName') or '')
            m = re.search('(\\d+)', name)
            if m and '积分' in name:
                total += int(m.group(1))
            drew += 1
            if r.get('code') != 0:
                break
        return {'drawn': drew, 'points': total}
    AI_MAX_TOKENS_DEF = 512

    @staticmethod
    def _ai_config():
        key = os.environ.get('AI_API_KEY', '')
        base = os.environ.get('AI_BASE_URL', '')
        if not key or not base:
            return None
        return {'key': key, 'base': base.rstrip('/'), 'model': os.environ.get('AI_MODEL', '')}

    def _ai_answer(self, content: str, options: List[Dict[str, Any]]) -> Optional[str]:
        """问 AI：返回**选项的 key**（A/B/C/D）；失败/不确定返回 None（走下一级）。

        ★ 兼容推理模型（deepseek-v4.1 等）：
        * `max_tokens=512`（思考约 25 token + 答案 1 token，够用）；
        * 优先读 `message.content`，为空时**回退读 `reasoning_content` 末尾**——
          有些网关把最终答案也放进思考通道。
        Prompt 设计：只能从给定选项选、输出单字母、常识 quiz 场景。
        """
        cfg = self._ai_config()
        if not cfg:
            return None
        opts_txt = '\n'.join((f"{o.get('key')}. {o.get('value')}" for o in options))
        prompt = f'你是答题助手。从下面选项中选出正确答案，只输出选项字母（如 B），不要任何其它内容。\n\n题目：{content}\n{opts_txt}'
        try:
            r = self.s.post(cfg['base'] + '/chat/completions', headers={'Authorization': 'Bearer ' + cfg['key'], 'Content-Type': 'application/json'}, json={'model': cfg['model'], 'temperature': 0, 'max_tokens': self.AI_MAX_TOKENS_DEF, 'messages': [{'role': 'user', 'content': prompt}]}, timeout=30)
            body = r.json()
            msg = (body.get('choices') or [{}])[0].get('message') or {}
            txt = str(msg.get('content') or '').strip().upper()
            if not txt:
                rc = str(msg.get('reasoning_content') or '').strip()
                if rc:
                    tail = rc[-60:].upper()
                    m = re.search('([A-Z])(?:\\W|$)', tail)
                    if m:
                        txt = m.group(1)
            m = re.match('^([A-Z])(?:\\W|$)', txt) or re.match('^([A-Z])$', txt)
            if not m:
                return None
            k = m.group(1)
            valid = {str(o.get('key')) for o in options}
            return k if k in valid else None
        except Exception:
            return None

    def question(self,activity_id=None,site_id=None) -> Dict[str, Any]:
        """积分答题 · 三级策略：🤖 AI → 📖 知识库 → 🎲 兜底 A + 答错学习。

        * AI 命中且答对 → 顺便把正解写进知识库（下次离线也对）；
        * AI 不可用/失败 → 知识库命中直答；
        * 都没有 → 兜底 A，答错后从服务端 rightAnswer 学习回填。
        """
        aid, site = (activity_id or '703318389396865152', site_id or 'wk240410b3206fb4')
        if not hasattr(self,'answered_activities'):self.answered_activities=set()
        self.answered_activities.add((site,aid))
        secret = 'OnjzJBzkMzMviJDe3FlZo4cnHOiZZDZswxq/wBfcpKLvAOp70yTcwXrRQm+ffp/ZTsdtROyC0VitlgF0bkY9tg=='
        algorithm=hashlib.sha1
        if aid!='703318389396865152':
            from .activities import question_crypto
            crypto=question_crypto(self,site,aid)
            secret=crypto.get('secretKey')
            algorithm={'HmacSHA1':hashlib.sha1,'HmacSHA256':hashlib.sha256}.get(crypto.get('algorithm'))
            if not secret or algorithm is None:return {'err':'活动配置未提供可用的答题签名规则，保留待处理'}
        # Starting a quiz may deduct points. Only an explicitly free round is automatic.
        info=self._wk('/wukongapc/question/user/info',params={'activityId':aid,'siteId':site})
        data=info.get('data') if isinstance(info,dict) else None
        if not isinstance(data,dict) or data.get('deductPoint') is None:
            return {'skip':'答题未明确提供参与费用，默认不启动'}
        try:cost=float(data['deductPoint'])
        except (TypeError,ValueError):return {'skip':'答题费用无法确认，默认不启动'}
        if cost!=0:return {'skip':'答题需要消耗积分，默认关闭'}
        kb = self._kb_load()
        ai_cfg = self._ai_config()
        ai_used = ai_hit = ai_right = 0
        d0 = self._wk('/wukongapc/question/user/start', method='POST', body={'activityId': aid, 'siteId': site})
        tok = (d0.get('data') or {}).get('answerToken')
        if not tok:
            return {'err': d0.get('msg') or 'start 无 answerToken'}
        right, pts, learned = (0, 0, 0)
        seen_questions=set()
        while True:
            q = self._wk('/wukongapc/question/user/question/pull', params={'activityId': aid, 'answerToken': tok, 'siteId': site}).get('data') or {}
            qid = q.get('questionId')
            if not qid:
                break
            if qid in seen_questions:return {'answered_right':right,'points':pts,'err':'平台重复下发同一道题，停止本轮并保留未完成状态'}
            seen_questions.add(qid)
            content = str(q.get('content') or '')
            options = q.get('options') or []
            ans = None
            if ai_cfg and content not in kb:
                ai_used += 1
                ans = self._ai_answer(content, options)
                if ans:
                    ai_hit += 1
            if ans is None and content in kb:
                for o in options:
                    if str(o.get('value')) == kb[content]:
                        ans = o.get('key')
                        break
            ans = ans or 'A'
            st = self._wk('/wukongapc/activity/config/sign/token', params={'activityId': aid, 'apiName': 'submitAnswer', 'siteId': site}).get('data') or ''
            fs = {'activityId': aid, 'questionId': qid, 'apiName': 'submitAnswer', 'userAnswer': ans, 'answerToken': tok, 'aladdinToken': st, 'siteId': site}
            plain = ''.join((f'{k}{v}' for k, v in sorted(fs.items())))
            sign = hmac.new(secret.encode(), plain.encode(), algorithm).hexdigest()
            aladdin = f'apiName=submitAnswer&signature={sign}&aladdinToken={st}'
            self._gap()
            try:
                r = self.s.post(WUKONGAPI + '/wukongapc/question/user/submit', params={'t': now_ms()}, json={'activityId': aid, 'questionId': qid, 'userAnswer': ans, 'answerToken': tok, 'siteId': site}, headers={'User-Agent': self.ua_space, 'Content-Type': 'application/json', 'Referer': H5_REFERER, 'aladdin_sign': aladdin}, timeout=25).json()
            except Exception as e:
                return {'answered_right': right, 'learned': learned, 'err': str(e)[:100]}
            if str(r.get('code')) != '0':
                return {'answered_right': right, 'learned': learned, 'err': r.get('msg')}
            dd = r.get('data') or {}
            if dd.get('rightFlag'):
                right += 1
                pts += int(dd.get('gotPoints') or 0)
                if content not in kb:
                    for o in options:
                        if o.get('key') == ans and o.get('value') is not None:
                            kb[content] = str(o.get('value'))
                            learned += 1
                            break
            elif dd.get('rightAnswer'):
                for o in options:
                    if o.get('key') == dd.get('rightAnswer') and o.get('value') is not None:
                        kb[content] = str(o.get('value'))
                        learned += 1
                        break
            if (dd.get('remainQuesNum') or 0) <= 0:
                break
            time.sleep(1.0)
        if learned:
            self._kb_save(kb)
        if hasattr(self,'checkpoint_save'):self.checkpoint_save('question:'+site+':'+aid)
        out: Dict[str, Any] = {'answered_right': right, 'points': pts, 'learned': learned}
        if ai_cfg:
            out['ai'] = f'{ai_hit}/{ai_used} 命中'
        return out

    def powerball(self) -> Dict[str, Any]:
        """彩票：开奖检查 + 中奖订单确认提交 + 订阅开奖提醒。

        源码（chunk16）：开奖后 `popup.do` 返回 `drawResultVOList`，
        对每条中奖 `toConfirm.do` → `submit.do` 领实物奖（填地址）。
        本轮纯协议范围：中奖检查 + 开奖订阅 + 弹窗提醒关闭；
        `submit.do` 需要 addressId（收货地址），本轮不动真实下单。
        """
        out: Dict[str, Any] = {}
        h = {'User-Agent': self.ua_space, 'Referer': 'https://zhan.vivo.com.cn/point/wk2305190f212481'}
        try:
            self._gap()
            r = self.s.get(POINTACT + '/api/powerball/baseInfo.do', params={'activityId': 26}, headers=h, timeout=25).json()
        except Exception as e:
            return {'err': str(e)[:100]}
        out['isLogin'] = (r.get('data') or {}).get('isLogin')
        out['periodBet'] = (r.get('data') or {}).get('todayOrPeriodBetNumber')
        try:
            pop = self.s.get(POINTACT + '/api/powerball/user/popup.do', params={'t': now_ms(),'activityId':26}, headers=h, timeout=25).json()
            wins = (pop.get('data') or {}).get('drawResultVOList') or []
            out['wins'] = [{'prizeId': w.get('prize', {}).get('id'), 'level': w.get('prize', {}).get('level'), 'itemType': w.get('prize', {}).get('itemType')} for w in wins if isinstance(w, dict)]
        except Exception:
            pass
        try:
            self._gap()
            r2 = self.s.post(POINTACT + '/api/activity/subscribe.do', params={'t': now_ms()}, json={'activityType': 6, 'activityId': 26, 'type': 1}, headers=h, timeout=25)
            out['subscribe'] = r2.json().get('code')
        except Exception:
            pass
        out['note'] = '下注需顶象 ticket（真机 WebView 通道），中奖确认/下单需收货地址'
        return out

    def guess_v2_receive(self) -> Dict[str, Any]:
        """竞猜 V2 中奖领奖（`/api/activity/guess/v2/receive.do`，GET）。

        源码（SPA `goReceive`）：中奖后该接口直接兑现实物/积分奖励到账户；
        未中奖/无待领时服务端返回业务码（幂等无害）。需带 `activityId`。
        """
        ga = (self._pm_get('/api/nmall/home/explicit/list.do').get('data') or {}).get('guessActivity') or {}
        aid = ga.get('id')
        if not aid:
            return {'skip': '无竞猜活动'}
        r = self.h5_call(POINTH5, '/api/activity/guess/v2/receive.do', params={'activityId': aid})
        if not r.get('retcode') and str(r.get('code') or '') == '':
            return {'skip': '无待领奖（接口已探测）'}
        return {'retcode': r.get('retcode'), 'msg': r.get('message') or r.get('msg')}

    def rank_prize_receive(self) -> Dict[str, Any]:
        """答题排行榜奖品领取（pointactivity `/api/rank/prize/receive.do`）。

        需 `rankId`（答题活动 id）与收货地址 `addressId`；仅尝试无地址的领奖路径。
        """
        h = {'User-Agent': self.ua_space, 'Referer': 'https://zhan.vivo.com.cn/point/wk240410b3206fb4'}
        try:
            self._gap()
            r = self.s.post(POINTACT + '/api/rank/prize/receive.do', params={'t': now_ms(), 'rankId': '703318389396865152'}, headers=h, timeout=25).json()
        except Exception as e:
            return {'_err': str(e)[:100]}
        return {'retcode': r.get('code', r.get('retcode')), 'msg': r.get('msg') or r.get('message')}

    def store_task_list_pub(self) -> Dict[str, Any]:
        """任务广场门店任务列表（`/api/store/task/list.do`，GET）。

        含门店导购可核销任务（taskSource=3）。配合 refreshStoreTaskCode 生成取货码。
        """
        r = self.h5_call(POINTH5, '/api/store/task/list.do')
        return {'retcode': r.get('retcode'), 'tasks': (r.get('data') or {}).get('tasks') or []}

    def consecutive_sign_receive(self) -> Dict[str, Any]:
        """连签奖励领取（sign `/api/sign/consecutive/receive.do`）。

        参数 `signAwardOrderNo` 来自连签活动页（SPA 路由 query），无该号时
        服务端回业务码——幂等探测即可。
        """
        businesses=[{'bizCode':'vivop','packageName':MAIN_SIGN_PKG},*self.sign_biz_list()]
        orders={};checks=[]
        def visit(value,biz,pkg):
            if isinstance(value,dict):
                if value.get('signAwardOrderNo') and value.get('received') is not True and value.get('isReceive') not in (True,1,'1') and value.get('canReceive') is not False:
                    orders[str(value['signAwardOrderNo'])]=(biz,pkg)
                for child in value.values():visit(child,biz,pkg)
            elif isinstance(value,list):
                for child in value:visit(child,biz,pkg)
        for business in businesses:
            biz=business.get('bizCode');pkg=business.get('packageName') or BIZ_PACKAGE.get(biz) or MAIN_SIGN_PKG
            info=self.h5_call(SIGNHOST,'/api/sign/info.do',params={'sysCode':biz},pkg=pkg)
            checks.append({'name':business.get('bizName') or biz,'code':info.get('code',info.get('retcode'))})
            visit(info.get('data'),biz,pkg)
        if not orders:return {'skip':'各业务当前无可领取的连签奖励单号','checks':checks}
        return {'checks':checks,'results':[{'name':biz,**self.h5_call(SIGNHOST,'/api/sign/consecutive/receive.do',method='POST',params={'signAwardOrderNo':order,'sysCode':biz},pkg=pkg)} for order,(biz,pkg) in orders.items()]}

    def sign_consecutive_info(self) -> Dict[str, Any]:
        """连签活动信息（`sign /api/sign/capital/pointInfo.do` 顺带返回连签档位）。

        ⚠️ `/api/sign/consecutive/info.do` 服务端不存在（返回 null）；
        连签真实数据在 `sign/home.do` 的 `totalDays/signDays` 里。
        """
        r = self.h5_call(POINTH5, '/api/sign/home.do', pkg=MAIN_SIGN_PKG)
        d = r.get('data') or {}
        return {'retcode': r.get('retcode'), 'totalDays': d.get('totalDays'), 'signDays': d.get('signDays'), 'dailyReward': d.get('dailyReward')}

    def phone_reward(self) -> Dict[str, Any]:
        """话费奖励（`/api/task/getPhoneReward.do`）。"""
        r = self.h5_call(POINTH5, '/api/task/getPhoneReward.do', method='POST', params={})
        return r

    def offline_task_receive(self) -> Dict[str, Any]:
        """线下任务族（`/offline/api/task/query.do` + `order/receive.do`）。

        query.do 返回当前可核销的线下订单（取货码任务等）；`receive.do` 按订单号核销。
        本轮只读 query（不自动核销，核销是导购动作）。
        """
        q = self.h5_call(POINTH5, '/offline/api/task/query.do')
        return {'status':'manual','reason':'线下订单由门店导购核销，服务器保留查询结果','query':q.get('data'),'retcode':q.get('retcode')}

    def wish_add(self, mall_item_id: Any=None) -> Dict[str, Any]:
        """商城收藏/心愿（`/api/wish/add.do`）。

        [520] 收藏1件商品的另一条协议路径（mall_favorite 之外的补充）。
        """
        if mall_item_id is None:
            cands = self.pm_exchangeable()
            if not cands:
                return {'skip': '无商品可收藏'}
            mall_item_id = cands[0]['itemId']
        r = self.h5_call(POINTH5, '/api/wish/add.do', method='POST', params={'mallItemId': mall_item_id})
        return {'retcode': r.get('retcode'), 'msg': r.get('message') or r.get('msg'), 'itemId': mall_item_id}

    def bbs_bean_exchange(self) -> Dict[str, Any]:
        """社区金豆兑换（`/api/bbsBean/exchange.do`）。"""
        idx = self.h5_call(POINTH5, '/api/bbsBean/index.do')
        d = idx.get('data') or {}
        bean = d.get('bean') or d.get('beans') or 0
        if not bean:
            return {'skip': '无金豆'}
        r = self.h5_call(POINTH5, '/api/bbsBean/exchange.do', method='POST', params={})
        return {'retcode': r.get('retcode'), 'msg': r.get('message') or r.get('msg'), 'bean': bean}

    def member_applet_benefits(self) -> Dict[str, Any]:
        """小程序会员权益族（`/api/applet/benefit/*`）—— 权益领取 + 深链弹窗。

        receiveByRisk 已在 member_claim_all 覆盖；这里补 mynew/myinfo/getAllDeepLinkToast
        三条与会员权益相关的辅助通道（动态枚举可领权益）。
        """
        out: Dict[str, Any] = {}
        h = {'User-Agent': self.ua_h5, 'Referer': MEMBER + '/wap/index', 'Origin': MEMBER, 'Content-Type': 'application/json;charset=UTF-8'}
        try:
            self._gap()
            my_new = self.s.get(MEMBER + '/api/applet/benefit/mynew.do', params={'t': now_ms()}, headers=h, timeout=20).json()
            d = (my_new.get('data') or {}).get('newBenefitList') or []
            out['new'] = len(d)
            got = []
            for b in d:
                bid = b.get('id') or b.get('benefitId')
                if not bid:
                    continue
                self._gap()
                r = self.s.post(MEMBER + '/api/applet/benefit/receiveByRisk.do', params={'t': now_ms()}, json={'benefitId': bid, 'version': '3.8'}, headers=h, timeout=20).json()
                got.append({'id': bid, 'retcode': r.get('retcode', r.get('code'))})
            out['got'] = got
        except Exception as e:
            out['_err'] = str(e)[:100]
        return out

    def xp_info(self) -> Dict[str, Any]:
        """会员成长值（`applet/xp/userInfo.do`，POST JSON）。"""
        h = {'User-Agent': self.ua_h5, 'Referer': MEMBER + '/wap/index', 'Origin': MEMBER, 'Content-Type': 'application/json;charset=UTF-8'}
        try:
            self._gap()
            ui = self.s.post(MEMBER + '/api/applet/xp/userInfo.do', params={'t': now_ms()}, json={}, headers=h, timeout=20).json()
            d = ui.get('data') or {}
            if isinstance(d, dict) and d:
                return {'level': d.get('levelName') or d.get('level'), 'xp': d.get('xp') or d.get('experience') or d.get('growthValue'), 'retcode': ui.get('retcode', ui.get('code'))}
            return {'retcode': ui.get('retcode', ui.get('code')) or '空响应', 'note': str(ui.get('message') or ui.get('msg') or '')[:30]}
        except Exception as e:
            return {'_err': str(e)[:60]}

    def ec_web_tasks(self) -> Dict[str, Any]:
        """EC 浏览任务：completeWebTask + ec/receivePoint（webTask==1 的任务）。"""
        done, earned = (0, 0)
        for bc, pn in PN_MAP.items():
            if cn_name(bc):
                continue
            tasks = self._ec_list(pn)
            for t in tasks:
                if t.get('webTask') != 1:
                    continue
                if int(t.get('completedTimes') or 0) >= int(t.get('totalTime') or 1):
                    continue
                c = self.h5_call(POINTH5, '/api/task/completeWebTask.do', method='POST', params={'taskKeyId': str(t.get('keyId') or t.get('taskKeyId'))})
                if str(c.get('retcode')) == '0':
                    body = {'noLoading': True, 'from': 'EC', 'taskId': t.get('id'), 'businessCode': bc}
                    for k in ('taskSource', 'type', 'subType'):
                        if t.get(k) is not None:
                            body[k] = t[k]
                    rv = self.h5_call(POINTH5, '/api/task/ec/receivePoint.do', method='POST', params=body)
                    earned += int((rv.get('data') or {}).get('rewardPoints') or 0)
                    done += 1
        return {'completed': done, 'earned': earned}

    def sdk_task_matrix(self) -> Dict[str, Any]:
        """★★ 全业务端 SDK action × 未完成任务矩阵穷举（动作后重读，进度变化即停）。

        ⚠️ 重量级：请求量 = 端 × 任务 × action × 3，可至上千次——仅在
          `VIVO_SDK_MATRIX=1` 时编排层才会调用；内部另有 `VIVO_SDK_MATRIX_MAX`
          请求上限硬保护（默认 800 次，防失控）。
        """
        hits = []
        budget = max(0, int(os.environ.get('VIVO_SDK_MATRIX_MAX') or 800))
        for bc, pkg in PN_MAP.items():
            if cn_name(bc):
                continue
            if budget <= 0:
                break
            tasks = [t for t in self._ec_list(pkg) if int(t.get('completedTimes') or 0) < int(t.get('totalTime') or 1) and t.get('webTask') != 1]
            if not tasks:
                continue
            actions = self._sdk_actions(pkg)
            if not actions:
                continue
            for t in tasks:
                if budget <= 0:
                    return {'completed': len(hits), 'details': hits, 'stop': f"请求上限 {os.environ.get('VIVO_SDK_MATRIX_MAX') or 800} 已到"}
                tid = t.get('id')
                need = max(1, int(t.get('totalTime') or 1) - int(t.get('completedTimes') or 0))
                before = int(t.get('completedTimes') or 0)
                for aid in actions:
                    if budget <= 0:
                        break
                    budget -= 3
                    self._sdk_upload(pkg, aid, need)
                    self._sdk_receive(pkg, aid)
                    after_t = next((x for x in self._ec_list(pkg) if x.get('id') == tid), None)
                    now = int((after_t or {}).get('completedTimes') or 0)
                    if now != before:
                        hits.append({'bc': bc, 'task': tid, 'name': t.get('name'), 'actionId': aid, 'before': before, 'after': now})
                        break
        return {'completed': len(hits), 'details': hits}

    def sdk_reward_precise(self) -> Dict[str, Any]:
        """★★ 逐 actionId upload+receive 并读积分变化，返回真实给分清单与合计。

        ⚠️ 重量级（仅在 `VIVO_SDK_MATRIX=1` 时调用）。2026-10-13 优化：
          ① 不再逐 actionId 前后双读积分（pm_points 每端只读 2 次），
            改为**一轮结束统一对比** + per-action receive 响应内 retcode==0 记命中；
          ② 加 `VIVO_SDK_MATRIX_MAX` 请求上限硬保护（默认 800）。
        """
        pm = self
        before = pm.pm_points()
        hits = []
        total = 0
        budget = max(0, int(os.environ.get('VIVO_SDK_MATRIX_MAX') or 800))
        for pkg in dict.fromkeys(list(PN_MAP.values()) + ['com.vivo.space']):
            if budget <= 0:
                break
            for aid in self._sdk_actions(pkg):
                if budget <= 0:
                    break
                budget -= 2
                self._sdk_upload(pkg, aid, 5)
                r = self._sdk_receive(pkg, aid)
                if str(r.get('retcode')) == '0' or str(r.get('code')) == '0':
                    hits.append({'pkg': pkg, 'actionId': aid})
        after = pm.pm_points()
        total = after - before if after is not None and before is not None and (before >= 0) and (after >= 0) else 0
        return {'before': before, 'after': after, 'total_gain': total, 'hits': hits}

    def _sdk_actions(self, pkg: str) -> List[str]:
        """拉某业务端的全部 actionId（`/sdk/config/action/list`）。

        ★ 2026-10-13 修复：这段代码此前因 `def` 签名行丢失，粘在
          `sdk_reward_precise` 的 `return` 之后成为不可达死代码——
          `_sdk_actions` 方法不存在，`sdk_task_matrix` / `sdk_reward_precise`
          每账号必抛 `AttributeError: '_sdk_actions'`（1631 账号全量复现）。
          实测修复后该通道恢复（参照 2026-10-12 实测：1892 → 1989，+97 分）。
        """
        r = self.h5_call(POINTSDK, '/sdk/config/action/list', method='POST', params={'pkgName': pkg})
        return [a.get('actionId') for a in (r.get('data') or {}).get('actions') or [] if a.get('actionId')]

    def _sdk_upload(self, pkg: str, aid: str, count: int=1) -> Dict[str, Any]:
        if pkg=='com.vivo.space':return self._native_sdk('/sdk/action/upload',pkg,aid,count)
        return self.h5_call(POINTSDK, '/sdk/action/upload', method='POST',pkg=pkg, params={'openid': self.acct.openid, 'token': self.acct.vivotoken, 'pkgName': pkg, 'actionId': aid, 'count': str(count), 'notifyPattern': '1'})

    def _sdk_receive(self, pkg: str, aid: str) -> Dict[str, Any]:
        if pkg=='com.vivo.space':return self._native_sdk('/sdk/task/receive/point',pkg,aid)
        return self.h5_call(POINTSDK, '/sdk/task/receive/point', method='POST',pkg=pkg, params={'openid': self.acct.openid, 'token': self.acct.vivotoken, 'pkgName': pkg, 'actionId': aid, 'notifyPattern': '1'})

    def _native_sdk(self,path,pkg,aid,count=None):
        from .taskflow.vendor.vivo import jvq
        device=self.acct.device
        payload={'appVersion':'13415','appVersionName':'13.4.1.5','sdkVerName':'1.3.6.0','sdkVerCode':'1360',
          'adrVerName':str(device['sdk_int']),'av':str(device['android_ver']),'model':device['model'],
          'openid':self.acct.openid,'token':self.acct.vivotoken,'pkgName':pkg,'actionId':str(aid),'notifyPattern':'0'}
        if count is not None:payload['count']=str(count)
        envelope=jvq.b64_flag11(jvq.seckey_bytes(json.dumps(payload,separators=(',',':')).encode(),pkg_name=pkg))
        response=self.s.post(POINTSDK+path,json={'jvq_param':envelope},headers=self._h5_headers(pkg),timeout=25).json()
        if isinstance(response,dict) and response.get('jvq_response'):response=json.loads(jvq.decrypt_response(response['jvq_response']))
        return response
    STORE_LNG = '116.407526'
    STORE_LAT = '39.904030'
    STORE_CITY = '北京'

    def store_list(self, lng: str='', lat: str='') -> List[Dict[str, Any]]:
        """POST /api/store/selected/list.do —— 门店列表（必须带经纬度，否则 1082）。"""
        r = self.h5_call(POINTWAP, '/api/store/selected/list.do', method='POST', params={'lng': lng or self.STORE_LNG, 'lat': lat or self.STORE_LAT, 'pageNo': 1, 'pageSize': 20, 'from': 'EC', 'businessCode': 'vivop', 'city': self.STORE_CITY, 'vkCityId': ''})
        return r.get('data') or [] if str(r.get('retcode')) == '0' else []

    def store_task_list(self, store_id: str, store_code: str) -> List[Dict[str, Any]]:
        """带门店上下文拉 EC 任务列表 —— taskSource=3 的门店任务只在该形态下出现。"""
        self._gap()
        try:
            r = self.s.get(POINTWAP + '/api/task/ec/taskList.do', params={'t': now_ms(), 'from': 'EC', 'type': 1, 'businessCode': 'vivop', 'tasks': '', 'storeId': str(store_id), 'storeCode': str(store_code)}, headers={'User-Agent': self.ua_h5, 'Referer': H5_ORIGIN + '/', 'cookie': self.cookie_header(MAIN_SIGN_PKG)}, timeout=20)
            return (r.json().get('data') or {}).get('tasks') or []
        except Exception:
            return []

    def store_task_codes(self, task_id: Any=276) -> Dict[str, Any]:
        """GET /api/task/refreshStoreTaskCode.do —— 刷新门店任务取货码（协议侧终点）。

        实测不带 vvc_pn（真实包名）会 1010 用户未登录。
        """
        r = self.h5_call(POINTWAP, '/api/task/refreshStoreTaskCode.do', params={'taskId': task_id, 'noLoading': True}, pkg=MAIN_SIGN_PKG)
        return {'retcode': r.get('retcode'), 'code': (r.get('data') or {}).get('code')}

    def store_tasks(self) -> Dict[str, Any]:
        """门店任务全流程：取最近门店 → 拉门店任务 → 刷新取货码（供导购扫码）。"""
        stores = self.store_list()
        if not stores:
            return {'err': '1082/无门店（store_list 需有效经纬度）'}
        st = stores[0]
        sid, sc = (str(st.get('storeId')), st.get('storeCode'))
        tasks = [t for t in self.store_task_list(sid, sc) if t.get('taskSource') == 3]
        out: Dict[str, Any] = {'status':'manual','reason':'需真实到店购买，导购扫码后计分','store': st.get('name'), 'storeId': sid, 'storeTasks': []}
        known_ids = {'301': 276, '306': 276}
        for t in tasks:
            tid = int(t.get('id') or 0) or known_ids.get(str(t.get('subType')))
            entry = {'name': t.get('name'), 'subType': t.get('subType'), 'completed': str(t.get('completedTimes')) + '/' + str(t.get('totalTime'))}
            if int(tid) > 0:
                code = self.store_task_codes(tid)
                entry['pickCode'] = code.get('code')
                entry['note'] = '码给导购扫后按实付1:1计分，须到店购买（线下闭环）'
            else:
                entry['note'] = '服务端未投放该任务的取货码（id=0）'
            out['storeTasks'].append(entry)
        return out

    def _ec_list(self, pn: str) -> List[Dict[str, Any]]:
        self._gap()
        from pathlib import Path
        cities=json.loads(Path(__file__).with_name('cities.json').read_text(encoding='utf-8'))
        city=self.acct.city or ''
        params={'t':now_ms(),'from':'EC','type':0,'tasks':''}
        if city and city not in ('全国','未知'):
            city=next((name for name in cities if city==name or city in name),city)
            cid=self.acct.vk_city_id or cities.get(city,'')
            if cid:params.update(city=city,vkCityId=cid)
        r=self.s.get(POINTWAP+'/api/task/ec/taskList.do',params=params,headers={'User-Agent':self.ua_h5,'Referer':H5_ORIGIN+'/','cookie':self.cookie_header(pn)},timeout=20)
        data=r.json()
        if not self.ok(data) or not isinstance((data.get('data') or {}).get('tasks'),list):raise ValueError('EC 任务目录查询未成功，不能当作无任务')
        return data['data']['tasks']

    def mall_favorite(self) -> Dict[str, Any]:
        self._gap()
        try:
            cfg = self.s.get(MSHOPACT + '/tool/config', headers={'User-Agent': self.ua_wap}, timeout=15).json()
            tc = json.loads((cfg.get('data') or {}).get('tempCookies') or '{}')
            if tc.get('cookieId'):
                self.s.cookies.set('vivo_fe_vftcookid', tc['cookieId'], domain='.vivo.com.cn')
            if tc.get('fakeSessionId'):
                self.s.cookies.set('vivo_fe_vftsessionid', tc['fakeSessionId'], domain='.vivo.com.cn')
        except Exception as e:
            return {'err': '商城会话失败:' + str(e)[:80]}
        pairs = self._shop_pairs()
        if not pairs:
            return {'err': '无商品对'}
        spu, sku = pairs[0]
        tok = ''
        try:
            tok = str(self.s.get(SHOP_FBAPI + '/v1/my/token', headers={'User-Agent': self.ua_wap}, timeout=15).json().get('data') or '')
        except Exception:
            pass
        self._gap()
        try:
            r = self.s.post(SHOP_FBAPI + '/v2/my/favorite/add', params={'skuId': str(sku), 'spuIds': str(spu), 'token': tok}, headers={'User-Agent': self.ua_wap, 'Referer': 'https://shop.vivo.com.cn/wap/index.html'}, timeout=15).json()
        except Exception as e:
            return {'err': str(e)[:80]}
        return {'spuId': spu, 'skuId': sku, 'code': r.get('code'), 'pointsReward': (r.get('data') or {}).get('pointsReward')}

    def _shop_pairs(self) -> List[Tuple[str, str]]:
        self._gap()
        try:
            r = self.s.post(EDEN + '/v3/home/index', data=self._eden_signed({'pageNum': '1', 'cfrom': '652'}), headers={'User-Agent': self.ua_space, 'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8'}, timeout=20)
            txt = json.dumps(r.json(), ensure_ascii=False)
        except Exception:
            return []
        seen, pairs = (set(), [])
        for m in re.finditer('/wap/product/(\\d+)\\?skuId=(\\d+)', txt):
            p = (m.group(1), m.group(2))
            if p not in seen:
                seen.add(p)
                pairs.append(p)
        return pairs[:20]

    def _member(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        self._gap()
        h = {'User-Agent': self.ua_space, 'Referer': MEMBER + '/wap/index', 'Origin': MEMBER, 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'}
        try:
            return self.s.post(MEMBER + '/api' + path, data=data, headers=h, timeout=20).json()
        except Exception as e:
            return {'_err': str(e)[:100]}

    def _member_json(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        self._gap()
        h = {'User-Agent': self.ua_space, 'Referer': MEMBER + '/wap/index', 'Content-Type': 'application/json', 'channel': '1', 'vivo_member_source_type': 'VIVO_PLUS_MINI_APP', 'mina_openid': self.acct.openid, 'mina_vivotoken': self.acct.vivotoken}
        try:
            return self.s.post(MEMBER + '/api' + path, json=data, headers=h, timeout=20).json()
        except Exception as e:
            return {'_err': str(e)[:100]}

    def _eden_signed(self, params: Dict[str, Any]) -> Dict[str, str]:
        p = dict(params)
        p.update(self._base_params())
        p['sign'] = m_value_for_post(p, FORUM_SIG_KEY)
        return p

    def _base_params(self) -> Dict[str, Any]:
        d=self.acct.device
        return {'imei': self.acct.imei, 'oaid': self.acct.oaid, 'model': d['model'], 'av': str(d['sdk_int']), 'an': str(d['android_ver']), 'pkgName': 'com.vivo.space', 'brand': d['brand'], 'density': d['density'], 'screensize': d['screensize'], 'nt': d['net_type'], 'app_ver': '13415', 'pictype': 'webp', 'elapsedtime': str(now_ms() % (1 << 31)), 'gitId': 'b80d0b7c310fcfe9e274db81863eba4b33a2b503'}

    def _eden_post(self, path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self._gap()
        try:
            r = self.s.post(EDEN + '/' + path, data=self._eden_signed(params), headers={'User-Agent': self.ua_space, 'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8'}, timeout=20)
            return r.json()
        except Exception:
            return {}

    def welfare_projects(self) -> List[Dict[str, Any]]:
        d = self._pm_get('/api/welfare/project/list.do').get('data')
        return d if isinstance(d, list) else []

    def welfare_contribute(self, points: int=1) -> Dict[str, Any]:
        """向第一个在办公益项目捐 `points` 分（默认 1 分，量小无害）。"""
        if points <= 0:
            return {'skip': 'points<=0'}
        ps = self.welfare_projects()
        if not ps:
            return {'skip': '无公益项目'}
        p = next((x for x in ps if x.get('key')), ps[0])
        r = self._pm_post('/api/welfare/contribute.do', key=p.get('key'), points=int(points))
        return {'project': p.get('title') or p.get('key'), 'points': points, 'retcode': r.get('retcode')}
    WK_Q = 'https://wukongapi.vivo.com.cn'

    def _wk_site_ids(self) -> List[str]:
        """从三个发现面收集全部 wk 站点码（去重保序）。"""
        ids: List[str] = []

        def grab(blob: str) -> None:
            for m in re.findall('(wk[0-9a-z]{10,16})', str(blob)):
                if m not in ids:
                    ids.append(m)
        try:
            for b in (self._member('/home/page/v5/bannerInfo.do', {}).get('data') or {}).get('bannerList') or []:
                grab(str(b.get('targetUrl') or '') + str(b.get('imageUrl') or ''))
        except Exception:
            pass
        try:
            for b in self.sign_biz_list():
                grab(str(b.get('selfJumpUrl') or '') + str(b.get('thirdJumpUrl') or ''))
        except Exception:
            pass
        try:
            ci = self._member('/homepage/commonInfo.do', {}).get('data') or {}
            grab(str(ci.get('suspension') or {}))
        except Exception:
            pass
        for path in ('/api/nmall/home/page/head.do', '/api/nmall/home/activity/zone.do'):
            try:
                blob = json.dumps(self._pm_get(path), ensure_ascii=False)
                grab(blob)
            except Exception:
                pass
        return ids

    def wk_site_online(self, site_id: str) -> Optional[int]:
        """站点在线状态：state ∈ {4,6} = 已下线；返回 None = 查询失败。"""
        self._gap()
        try:
            r = self.s.get(self.WK_Q + '/wukongtopic/site/online/query', params={'siteId': site_id, 'noTimestamp': 'true'}, headers={'User-Agent': self.ua_h5, 'Referer': H5_ORIGIN + '/'}, timeout=20)
            st = (r.json().get('data') or {}).get('state')
            return int(st) if st is not None else None
        except Exception:
            return None

    def wk_site_activity_ids(self, site_id: str) -> List[str]:
        """从站点配置里提取全部 activityId（去重）。"""
        self._gap()
        try:
            r = self.s.get(self.WK_Q + '/wukongtopic/site/config/query', params={'siteId': site_id, 'noTimestamp': 'true'}, headers={'User-Agent': self.ua_h5, 'Referer': H5_ORIGIN + '/'}, timeout=20)
            blob = json.dumps(r.json(), ensure_ascii=False)
            return sorted(set(re.findall('"activityId"\\s*:\\s*"?(\\w{10,})', blob)))
        except Exception:
            return []

    def wk_lottery_available(self, activity_id: str, site_id: str, group_id: int=0) -> int:
        q = {'activityId': activity_id, 'siteId': site_id}
        if group_id:
            q['groupId'] = group_id
        d = self._wk('/wukongapc/lottery/user/available/query', params=q).get('data') or {}
        return int(d.get('freeAvaCnt') or 0) + int(d.get('taskAvaCnt') or 0)

    def wk_lottery_draw(self, activity_id: str, site_id: str, referer: str='',group_id: int=0) -> Dict[str, Any]:
        self._gap()
        body = {'activityId': activity_id, 'topicId': site_id, 'siteId': site_id, 'extend': {'hostUrl': (referer or H5_ORIGIN + '/point/' + site_id) + '&h5JumpBackFlag=1', 'locationAuthorizedDTO': {'hasUserLocation': False, 'province': '', 'city': ''}}}
        if group_id:body['groupId']=group_id
        try:
            r = self.s.post(WUKONGAPI + '/wukongapc/lottery/draw', params={'t': now_ms()}, json=body, headers={'User-Agent': self.ua_h5, 'Content-Type': 'application/json;charset=UTF-8', 'Referer': referer or H5_ORIGIN + '/point/' + site_id, 'cookie': self.cookie_header()}, timeout=25)
            return r.json()
        except Exception as e:
            return {'_err': str(e)[:100]}

    def wk_lottery_sweep(self) -> Dict[str, Any]:
        """★★ 悟空站点 sweep：全部发现面 → 在线站 → activityId → 免费次数全抽。

        对每个 (activityId, siteId) 组合查 `lottery/user/available/query`
        （双11族要 `groupId=1`，普通族不带 group —— 两种口径都试，有次数的才抽），
        `14001 无抽奖机会` / `code:1000`（站点无 lottery 插件）都自然跳过。
        砸金蛋（wk241209756168f3）与双11（wk2609233beab7e8）也在这张表里，
        与固化的 golden_egg()/double11() 双保险（同 activityId 幂等，多抽无害）。
        """
        draws: List[Dict[str, Any]] = []
        sites = self._wk_site_ids()
        for site in sites:
            if self.wk_site_online(site) in (4, 6):
                continue
            for aid in self.wk_site_activity_ids(site):
                for group in (0, 1):
                    try:
                        av = self.wk_lottery_available(aid, site, group_id=group)
                    except Exception:
                        continue
                    if av <= 0:
                        continue
                    drew, points = (0, 0)
                    for _ in range(av):
                        r = self.wk_lottery_draw(aid, site,group_id=group)
                        name = str((r.get('data') or {}).get('rewardName') or '')
                        if str(r.get('code')) == '0':
                            drew += 1
                            m = re.search('(\\d+)', name)
                            if m and '积分' in name:
                                points += int(m.group(1))
                            draws.append({'site': site, 'activityId': aid, 'group': group, 'reward': name})
                        else:
                            break
                    if not drew and group == 0:
                        continue
                    if drew:
                        break
        total_pts = 0
        for d in draws:
            m = re.search('(\\d+)', str(d.get('reward') or ''))
            if m and '积分' in str(d.get('reward') or ''):
                total_pts += int(m.group(1))
        return {'sites': len(sites), 'draws': draws, 'points': total_pts}

    def pm_exchangeable(self) -> List[Dict[str, Any]]:
        budget = max(0, self.pm_points())
        seen, out = (set(), [])
        for cat in self.pm_categories():
            cid = cat.get('id')
            ch = str(cat.get('channel') or 'point').lower()
            ch2, src = ('point', 0) if ch == 'point' else ('EC', 4)
            for it in self.pm_items(cid):
                if it.get('playMethod') != 0:
                    continue
                price = it.get('finalPoints')
                if price is None or price > budget:
                    continue
                if (it.get('availStock') or 0) <= 0:
                    continue
                if it.get('id') in seen:
                    continue
                seen.add(it.get('id'))
                out.append({'itemId': it.get('id'), 'name': it.get('name'), 'price': price, 'categoryId': cid, 'channel': ch2, 'source': src})
        out.sort(key=lambda x: (x['price'], x['itemId']))
        return out

    def pm_exchange_auto(self, max_price: int=5, limit: int=2, sms_code: str='') -> Dict[str, Any]:
        """把预算内（默认 ≤5 分）的可兑条目自动兑换（默认至多 2 个）。

        遇 `1034 未通过短信验证` 就停（返回 sms_needed=True）；
        提供了 `sms_code`（VIVO_SMS_CODE 环境变量）则先 verify 再兑。
        """
        cands = [x for x in self.pm_exchangeable() if x['price'] <= max_price][:limit]
        if not cands:
            return {'skip': '预算内无可兑条目'}
        done: List[Dict[str, Any]] = []
        for x in cands:
            r = self._pm_enc('/api/mall/item/exchange.do', {'itemId': x['itemId'], 'categoryId': x['categoryId'], 'ticket': '', 'constId': '', 'scene': '', 'arpuId': '', 'cpdTaskKeyId': '', 'channel': x['channel'], 'source': x['source']})
            if str(r.get('retcode')) == '1034':
                if not sms_code:
                    return {'results': done, 'sms_needed': True, 'note': '积分兑换需短信验证：把验证码设到 VIVO_SMS_CODE 再跑'}
                v = self._pm_post('/api/sms/verify.do', code=str(sms_code), scene='exchange')
                if str(v.get('retcode')) != '0':
                    return {'results': done, 'err': '短信验证失败: ' + str(v.get('message'))}
                r = self._pm_enc('/api/mall/item/exchange.do', {'itemId': x['itemId'], 'categoryId': x['categoryId'], 'ticket': '', 'constId': '', 'scene': '', 'arpuId': '', 'cpdTaskKeyId': '', 'channel': x['channel'], 'source': x['source']})
            done.append({'name': x['name'], 'price': x['price'], 'retcode': r.get('retcode'), 'orderId': (r.get('data') or {}).get('orderId')})
        return {'results': done}
    MEMBER_ZONE_TYPES = (1, 3, 4, 6)

    def member_claimable_home(self) -> List[Dict[str, Any]]:
        """home 聚合口径的可领权益（userStatus==0）。"""
        home = self._member('/home/page/v5/queryInfo.do', {})
        d = home.get('data') or {}
        items: List[Dict[str, Any]] = []
        for zc in (d.get('zoneInfo') or {}).get('zoneContentInfoList') or []:
            for c in zc.get('zoneCommodityInfoList') or []:
                if c.get('userStatus') == 0:
                    items.append(c)
        return items

    def member_zone_claimable(self) -> List[Dict[str, Any]]:
        """4 个 zone 专区的可领权益（type=1/3/4/6）。"""
        out: List[Dict[str, Any]] = []
        for ty in self.MEMBER_ZONE_TYPES:
            page=1;seen=set()
            while True:
                r = self._member_json('/home/page/v5/homePageZoneInfo.do', {'pageNo': page, 'type': int(ty)})
                d = r.get('data') or {}
                if not isinstance(d, dict):break
                zone=d.get('zoneInfo') or d
                rows=[item for group in zone.get('zoneContentInfoList') or [] for item in group.get('zoneCommodityInfoList') or []]
                identities={str(item.get('id') or item.get('benefitId') or item.get('receiveIds')) for item in rows}
                if not rows or identities.issubset(seen):break
                seen.update(identities)
                for item in rows:
                    if str(item.get('userStatus'))=='0':out.append({**item,'_zoneType':ty})
                more=d.get('hasMore',zone.get('hasMore',d.get('hasNextPage')))
                if str(more).lower() not in ('true','1') and not (d.get('totalPage') and page<int(d['totalPage'])):break
                page+=1
        return out

    def _member_receive_one(self, it: Dict[str, Any]) -> Dict[str, Any]:
        """按优先级领取单项权益（实测三种口）。"""
        if it.get('receiveIds'):
            ids = it['receiveIds']
            ids = ids if isinstance(ids, (list, tuple)) else [ids]
            return self._member('/benefit/v5/receiveCoupon.do', {'receiveIds': ','.join((str(i) for i in ids))})
        if it.get('benefitId'):
            return self._member('/benefit/v5/receiveFlashBenefit.do', {'benefitId': it['benefitId']})
        return self._member_json('/benefit/receiveByRisk.do', {'benefitId': it.get('id'), 'version': '3.8'})

    def member_claim_all(self) -> Dict[str, Any]:
        """★ 会员中心全量领取：home 聚合 + 4 个 zone 专区（去重后统一领）。

        ⚠️ 修复：原实现把 `member_claim()` 的 **dict 返回值**与 list 相加（TypeError），
        现改为分别收集 `member_claimable_home()` + `member_zone_claimable()` 两个 list。
        """
        merged: List[Dict[str, Any]] = []
        seen: set = set()
        try:
            src1 = self.member_claimable_home()
        except Exception:
            src1 = []
        try:
            src2 = self.member_zone_claimable()
        except Exception:
            src2 = []
        for it in list(src1) + list(src2):
            key = (it.get('id'), str(it.get('receiveIds')), it.get('benefitId'))
            if key in seen:
                continue
            seen.add(key)
            merged.append(it)
        done = []
        for it in merged:
            try:
                r = self._member_receive_one(it)
            except Exception as e:
                r = {'retcode': f'err:{str(e)[:30]}'}
            done.append({'name': it.get('name'), 'zone': it.get('_zoneType'), 'status':'completed' if self.ok(r) else 'failed','retcode': r.get('retcode',r.get('code')),'message':r.get('message') or r.get('msg')})
            time.sleep(0.4)
        return {'claimable': len(merged), 'results': done}

    def member_claim(self) -> Dict[str, Any]:
        """home 聚合口径领取（`member_claim_all` 的轻量版）。"""
        items = self.member_claimable_home()
        done = []
        for it in items:
            try:
                r = self._member_receive_one(it)
            except Exception as e:
                r = {'retcode': f'err:{str(e)[:30]}'}
            done.append({'name': it.get('name'), 'retcode': r.get('retcode')})
        return {'claimable': len(items), 'results': done}
    KB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'answer_kb.json')

    def _kb_load(self) -> Dict[str, str]:
        try:
            with VivoApi._KB_LOCK:
                return dict(json.loads(open(self.KB_PATH, encoding='utf-8').read()))
        except Exception:
            return {}
    _KB_LOCK = threading.Lock()

    def _kb_save(self, kb: Dict[str, str]) -> None:
        try:
            with VivoApi._KB_LOCK:
                with open(self.KB_PATH, 'w', encoding='utf-8') as f:
                    json.dump(kb, f, ensure_ascii=False, indent=1)
        except Exception:
            pass

    def question_gift(self) -> Dict[str, Any]:
        """答题排行礼物领取（`/wukongapc/question/rank/gift/receive`）。

        源码（`getMyPrize`）参数是 **`topicId`**（= 站点 id）而非 `siteId`。
        """
        aid, site = ('703318389396865152', 'wk240410b3206fb4')
        r = self._wk('/wukongapc/question/rank/gift/receive', params={'activityId': aid, 'topicId': site})
        return {'retcode': r.get('code'), 'msg': r.get('msg')}

    def crowdfunding_lucky(self) -> Dict[str, Any]:
        aid, site = ('907110737363599360', 'wk25102485f18bf0')
        cfg = self._wk('/wukongapc/crowdfunding/config/query', params={'activityId': aid, 'siteId': site})
        d = cfg.get('data') or {}
        status = d.get('activityStatus')
        if str(status) == '2':
            return {'skip': '本期夺宝已结束（activityStatus=2），开期后自动参与'}
        av = self._wk('/wukongapc/crowdfunding/lucky/available', params={'activityId': aid, 'siteId': site}).get('data') or {}
        n = int(av.get('availableCount') or 0)
        if n <= 0:
            return {'skip': '无可兑次数', 'activityStatus': status}
        r = self._wk('/wukongapc/crowdfunding/lucky/exchange', method='POST', body={'activityId': aid, 'siteId': site, 'count': n, 'hasUserLocation': False, 'province': '', 'city': ''})
        codes = r.get('data') if isinstance(r.get('data'), list) else []
        return {'exchanged': len(codes), 'codes': codes[:5]}

    def guess_subscribe(self) -> Dict[str, Any]:
        ga = (self._pm_get('/api/nmall/home/explicit/list.do').get('data') or {}).get('guessActivity') or {}
        if not ga.get('id'):
            return {'skip': '无竞猜活动'}
        self._gap()
        try:
            r = self.s.post(POINTACT + '/api/activity/subscribe.do', params={'t': now_ms()}, json={'activityType': 3, 'activityId': ga['id'], 'type': 1}, headers={'User-Agent': self.ua_h5, 'Referer': H5_ORIGIN + '/'}, timeout=20)
            return {'activity': ga.get('name'), 'code': r.json().get('code')}
        except Exception as e:
            return {'_err': str(e)[:100]}

    def coupon_remind(self) -> Dict[str, Any]:
        """¥1111 购机神券「提醒我」（mshopact /couponGrab/updateRemind，实测 code:200）。"""
        try:
            self._gap()
            q = self.s.get(MSHOPACT + '/couponGrab/queryActivity', params={'t': now_ms(), 'activityId': 88, 'style': 1, 'tabId': ''}, headers={'User-Agent': self.ua_h5, 'Referer': H5_ORIGIN + '/'}, timeout=20).json()
        except Exception as e:
            return {'_err': str(e)[:100]}
        tabs = (q.get('data') or {}).get('couponGrabTabList') or []
        now = now_ms()
        nxt = next((t for t in tabs if int(t.get('startTime') or 0) > now), None)
        if not nxt:
            return {'skip': '无未开抢场次'}
        m = re.search('"couponUuid"\\s*:\\s*"(\\w+)"', json.dumps(q, ensure_ascii=False))
        if not m:
            return {'skip': '无 couponUuid'}
        self._gap()
        try:
            r = self.s.get(MSHOPACT + '/couponGrab/updateRemind', params={'t': now_ms(), 'activityId': 88, 'couponUuid': m.group(1), 'tabId': nxt.get('id'), 'isRemind': 1}, headers={'User-Agent': self.ua_h5, 'Referer': H5_ORIGIN + '/'}, timeout=20)
            return {'tab': nxt.get('id'), 'startTime': nxt.get('startTime'), 'code': r.status_code}
        except Exception as e:
            return {'_err': str(e)[:100]}

    def wk_customize_sign(self, wk: str, sys_code: str, pn: str) -> Dict[str, Any]:
        self._gap()
        h = {'User-Agent': self.ua_h5, 'Referer': f'https://zhan.vivo.com.cn/point/{wk}', 'Origin': 'https://zhan.vivo.com.cn', 'Content-Type': 'application/x-www-form-urlencoded', 'cookie': self.cookie_header(pn)}
        try:
            r = self.s.post(SIGNHOST + '/api/sign/customize/sign.do', params={'t': now_ms()}, data={'sysCode': sys_code}, headers=h, timeout=15)
            return r.json()
        except Exception as e:
            return {'_err': str(e)[:100]}

    def sign_vivop(self) -> Dict[str, Any]:
        """第 12 端：vivo+（`wk2207264eeaa8ec`，dosign JSON {sysCode:"vivop"}，幂等 10003）。"""
        r = self.h5_call(SIGNHOST, '/api/sign/dosign.do', method='POST', params={'sysCode': 'vivop'}, pkg='com.vivo.space')
        ok = self.sign_ok(r)
        chk = self.h5_call(SIGNHOST, '/api/sign/info.do', params={'sysCode': 'vivop'}, pkg='com.vivo.space')
        info = chk.get('data') or {}
        return {'ok': ok, 'code': r.get('code'), 'todayIsSign': info.get('todayIsSign'), 'totalSignDay': info.get('totalSignDay')}

    def _wkapc(self, path: str, *, method: str='GET', params: Optional[Dict[str, Any]]=None, body: Optional[Dict[str, Any]]=None, referer: str='') -> Dict[str, Any]:
        """wukongapc 通用调用（预约活动族）。"""
        self._gap()
        a = self.acct
        ck = 'vivo_account_cookie_iqoo_openid=' + a.openid + ';vivo_account_cookie_iqoo_vivotoken=' + a.vivotoken + ';vivo_account_cookie_iqoo_authtoken=' + a.vivotoken + ';vivo_account_cookie_iqoo_checksum=' + a.vivotoken + ';vivo_account_cookie_iqoo_regioncode=CN' + ';vivo_account_cookie_wechat_from=108' + ';app_package=minip.vivop' + ';vvc_r=' + a.vivotoken + ';vvc_openid=' + a.openid + ';vvc_imei=' + self.acct.imei
        h = {'User-Agent': self.ua_h5, 'Origin': 'https://zhan.vivo.com.cn', 'Referer': referer or 'https://zhan.vivo.com.cn/', 'cookie': ck}
        url = WUKONGAPI + path + ('&' if '?' in path else '?') + 't=' + str(now_ms())
        try:
            if method.upper() == 'GET':
                return self.s.get(url, params=params or {}, headers=h, timeout=20).json()
            h['Content-Type'] = 'application/json'
            return self.s.post(url, json=body or {}, headers=h, timeout=20).json()
        except Exception as e:
            return {'_err': str(e)[:100]}
    NEW_APPOINTMENTS = [{'name': 'iQOO Neo12新品预约', 'activityId': '1033627166278945728', 'siteId': 'wk260928c41ab86a'}]

    def appointment_sign_all(self) -> Dict[str, Any]:
        """★★ 预约签到族：对每个预约活动读状态 → 未签则签 → 复核。

        返回每活动的 {day, total, todaySigned, reward}。幂等（已签返回 10000 不重复）。
        """
        out: List[Dict[str, Any]] = []
        for appt in self.NEW_APPOINTMENTS:
            p = {'activityId': appt['activityId'], 'siteId': appt['siteId']}
            ref = f"https://zhan.vivo.com.cn/vivospace/{appt['siteId']}"
            info = self._wkapc('/wukongapc/signin/user/info', params=p, referer=ref)
            d = info.get('data') or {}
            rec: Dict[str, Any] = {'name': appt['name'], 'day': d.get('signDays'), 'total': d.get('cycle'), 'todaySigned': d.get('todaySignFlag')}
            if not d.get('todaySignFlag'):
                r = self._wkapc('/wukongapc/signin/sign', method='POST', body=p, referer=ref)
                rec['sign_code'] = r.get('code')
                rec['reward'] = (r.get('data') or {}).get('rewardName')
                info2 = self._wkapc('/wukongapc/signin/user/info', params=p, referer=ref)
                rec['todaySigned'] = (info2.get('data') or {}).get('todaySignFlag')
            out.append(rec)
        return {'results': out}

    def appointment_lottery_all(self) -> Dict[str, Any]:
        """★★ 预约抽奖族：对每个预约活动查免费次数 → 全部抽完。

        返回每活动的 {free, draws:[rewardName]}。
        """
        out: List[Dict[str, Any]] = []
        for appt in self.NEW_APPOINTMENTS:
            p = {'activityId': appt['activityId'], 'siteId': appt['siteId']}
            ref = f"https://zhan.vivo.com.cn/vivospace/{appt['siteId']}"
            av = self._wkapc('/wukongapc/lottery/user/available/query', params=p, referer=ref)
            d = av.get('data') or {}
            free = int(d.get('freeAvaCnt') or 0) + int(d.get('taskAvaCnt') or 0)
            rec: Dict[str, Any] = {'name': appt['name'], 'free': free, 'draws': []}
            for _ in range(free):
                body = {'activityId': appt['activityId'], 'topicId': appt['siteId'], 'siteId': appt['siteId'], 'extend': {'hostUrl': ref + '&h5JumpBackFlag=1', 'locationAuthorizedDTO': {'hasUserLocation': False, 'province': '', 'city': ''}}}
                r = self._wkapc('/wukongapc/lottery/draw', method='POST', body=body, referer=ref)
                if str(r.get('code')) == '0':
                    rec['draws'].append((r.get('data') or {}).get('rewardName') or '')
                else:
                    rec['draws'].append({'code': r.get('code'), 'msg': r.get('msg')})
                    break
            out.append(rec)
        return {'results': out}

    def appointment_tasks_all(self) -> Dict[str, Any]:
        """★★ 预约页任务族：task/list → 浏览任务 task/finish（得抽奖次数/积分）。"""
        out: List[Dict[str, Any]] = []
        for appt in self.NEW_APPOINTMENTS:
            p = {'activityId': appt['activityId'], 'siteId': appt['siteId'], 'serialNumber': ''}
            ref = f"https://zhan.vivo.com.cn/vivospace/{appt['siteId']}"
            r = self._wkapc('/wukongapc/task/list', params=p, referer=ref)
            tasks = (r.get('data') or {}).get('taskList') or []
            rec: Dict[str, Any] = {'name': appt['name'], 'tasks': len(tasks), 'done': []}
            for t in tasks:
                if str(t.get('taskStatus')) == '1' or t.get('isRemoteTask'):
                    continue
                body = {'activityId': appt['activityId'], 'taskId': t.get('taskId'), 'appPkg': '', 'siteId': appt['siteId'], 'locationAuthorizedDTO': {'hasUserLocation': False, 'province': '', 'city': ''}}
                fr = self._wkapc('/wukongapc/task/finish', method='POST', body=body, referer=ref)
                if str(fr.get('code')) == '0':
                    rec['done'].append(t.get('taskName'))
            out.append(rec)
        return {'results': out}

    def appointment_comment_lottery(self) -> Dict[str, Any]:
        """★★ 评论抽奖族：预约页的「评论抽奖」tab（读评论区判断是否有可抽次数）。

        ⚠️ 发表评论属真实 UGC 行为（不能伪造），本方法只读可抽次数并抽完；
           若无可抽次数则跳过（如实报告）。
        """
        out: List[Dict[str, Any]] = []
        for appt in self.NEW_APPOINTMENTS:
            p = {'activityId': appt['activityId'], 'siteId': appt['siteId']}
            ref = f"https://zhan.vivo.com.cn/vivospace/{appt['siteId']}"
            av = self._wkapc('/wukongapc/lottery/user/available/query', params=p, referer=ref)
            d = av.get('data') or {}
            free = int(d.get('freeAvaCnt') or 0) + int(d.get('taskAvaCnt') or 0)
            out.append({'name': appt['name'], 'free': free, 'note': '评论发布属真实 UGC，不伪造' if free <= 0 else ''})
        return {'results': out}

def cn_name(code: str) -> bool:
    """判断是否为中文业务名"""
    return any(('一' <= ch <= '鿿' for ch in code))
