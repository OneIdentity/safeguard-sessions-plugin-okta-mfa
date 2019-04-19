#
#   Copyright (c) 2019 One Identity
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
from ..plugin import Plugin
from textwrap import dedent
import pytest


@pytest.fixture
def plugin(plugin_config):
    return Plugin(plugin_config)


@pytest.mark.interactive
def test_authenticate_using_push(plugin, okta_user, interactive):
    interactive.message("This is an end-to-end authentication request using Okta, please ACCEPT it")
    result = (plugin.authenticate(cookie={},
                                  session_cookie={},
                                  gateway_user=okta_user,
                                  client_ip="1.2.3.4",
                                  key_value_pairs={},
                                  protocol="ssh"))

    assert verdict(result) == "NEEDINFO"
    assert len(question(result)) == 3
    value, prompt, disable_echo = question(result)
    assert value == "otp"
    assert "Okta" in prompt
    assert disable_echo is False

    sc = session_cookie(result)

    result = (plugin.authenticate(cookie={},
                                  session_cookie=sc,
                                  gateway_user=okta_user,
                                  client_ip="1.2.3.4",
                                  key_value_pairs={'otp': ""},
                                  protocol="ssh"))

    assert verdict(result) == "ACCEPT"


def test_authenticate_using_otp(plugin, okta_user, totp_response):
    result = (plugin.authenticate(cookie={},
                                  session_cookie={},
                                  gateway_user=okta_user,
                                  client_ip="1.2.3.4",
                                  key_value_pairs={},
                                  protocol="ssh"))

    assert verdict(result) == "NEEDINFO"
    assert len(question(result)) == 3
    value, prompt, disable_echo = question(result)
    assert value == "otp"
    assert "Okta" in prompt
    assert disable_echo is False

    result = (plugin.authenticate(cookie={},
                                  session_cookie={},
                                  gateway_user=okta_user,
                                  client_ip="1.2.3.4",
                                  key_value_pairs={'otp': totp_response()},
                                  protocol="ssh"))

    assert verdict(result) == "ACCEPT"


def test_authenticate_denies_request_if_provider_is_known_but_not_set_up(plugin, okta_user):
    result = (plugin.authenticate(cookie={},
                                  session_cookie={},
                                  gateway_user=okta_user,
                                  client_ip="1.2.3.4",
                                  key_value_pairs={'otp': "r=rsaresponse"},
                                  protocol="ssh"))

    assert verdict(result) == "DENY"
    assert "Selected factor 'RSA' not found for user" in additional_metadata(result)


def verdict(v):
    return v['verdict']


def question(v):
    return v['question']


def additional_metadata(v):
    return v['additional_metadata']


def session_cookie(v):
    return v['session_cookie']


def session_cookie_questions(v, key=None):
    if key is None:
        return v['session_cookie']["questions"]
    else:
        return v['session_cookie']["questions"][key]
