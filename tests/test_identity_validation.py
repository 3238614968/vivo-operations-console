from types import SimpleNamespace

import pytest

from protocol.api import VivoApi
from protocol import runner


@pytest.mark.parametrize('response', [
    {'code': 0}, {'code': '200'}, {'retcode': 0},
    {'code': 31140003}, {'code': '31140003'},
    {'retcode': 31140003}, {'retcode': '31140003'},
])
def test_identity_accepts_success_and_unavailable_mpc_gateway(response):
    assert VivoApi.identity_ok(response)


@pytest.mark.parametrize('response', [
    None, [], [{'code': 31140003}], 'unavailable', 503, {},
    {'code': 1010}, {'retcode': 20002}, {'_err': 'network failure'},
    {'retcode': 1010, 'code': 31140003},
])
def test_identity_rejects_invalid_responses_without_raising(response):
    assert not VivoApi.identity_ok(response)


def test_mpc_gateway_exception_does_not_apply_to_business_operations():
    response = {'code': 31140003}
    assert not VivoApi.ok(response)
    assert not VivoApi.sign_ok(response)


def login_events(monkeypatch, replies, *, refresh=False):
    replies = iter(replies)
    renewals = []
    transport = SimpleNamespace(requests_count=0, unsafe_sent=False)
    api = SimpleNamespace(
        identity_ok=VivoApi.identity_ok,
        user_info=lambda: next(replies),
        pm_points=lambda: 10,
    )

    def renew(raw, *args):
        renewals.append(raw['vivotoken'])
        return {**raw, 'vivotoken': 'renewed-test-token'}

    monkeypatch.setattr(runner, 'transport_for', lambda payload: transport)
    monkeypatch.setattr(runner, 'make_api', lambda raw, session: api)
    monkeypatch.setattr(runner, 'renew', renew)
    events = list(runner.iter_events({
        'account': {'openid': 'test-owner', 'vivotoken': 'test-token',
                    '_pool': 'https://owned.test'},
        'action': 'login', 'profile': 'login', 'refresh_login': refresh,
    }))
    return events, renewals


def test_initial_mpc_gateway_response_continues_without_renewal(monkeypatch):
    events, renewals = login_events(monkeypatch, [{'code': 31140003}])
    assert not renewals
    assert events[-1] == {'type': 'result', 'points': 10, 'before': 10, 'gained': 0}


@pytest.mark.parametrize('first', [{'code': 1010}, [{'code': 31140003}]])
def test_automatic_renewal_accepts_mpc_gateway_response(monkeypatch, first):
    events, renewals = login_events(monkeypatch, [first, {'code': 31140003}])
    assert renewals == ['test-token']
    assert events[0]['type'] == 'credentials'
    assert events[-1]['type'] == 'result'
    assert events[-1]['points'] == 10


def test_explicit_renewal_accepts_mpc_gateway_response(monkeypatch):
    events, renewals = login_events(monkeypatch, [{'code': 31140003}], refresh=True)
    assert renewals == ['test-token']
    assert events[-1]['type'] == 'result'


def test_failed_renewal_still_stops_before_balance_read(monkeypatch):
    events, renewals = login_events(monkeypatch, [{'code': 1010}, {'code': 1010}])
    assert renewals == ['test-token']
    assert events[-1]['type'] == 'error'
    assert '登录态未通过平台校验' in events[-1]['message']
    assert not any(event['type'] in ('balance', 'result') for event in events)
