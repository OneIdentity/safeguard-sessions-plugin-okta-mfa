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
from ..client import Client
from safeguard.sessions.plugin.mfa_client import MFAAuthenticationFailure, MFAServiceUnreachable
from requests import RequestException
import pytest


@pytest.fixture
def inject_connection_error(mocker):
    request_mock = mocker.patch("lib.client.request")
    request_mock.side_effect = RequestException


@pytest.fixture
def okta_client(okta_api_url, okta_api_key, okta_application_id):
    return Client(api_url=okta_api_url,
                  application_id=okta_application_id,
                  api_key=okta_api_key)


@pytest.mark.interactive
def test_successful_push_authentication_results_in_success(okta_client, okta_user, interactive):
    interactive.message("We expect a successful Okta authentication now, so please Accept the push authentication")
    okta_client.push_authenticate(okta_user)


@pytest.mark.interactive
def test_successful_push_authentication_with_explicit_p_factor_results_in_success(okta_client, okta_user, interactive):
    interactive.message("We expect a successful Okta authentication now, so please Accept the push authentication")
    okta_client.otp_authenticate(okta_user, "p=")


def test_successful_otp_authentication_results_in_success(okta_client, okta_user, totp_response):
    okta_client.otp_authenticate(okta_user, totp_response())


def test_authentication_with_unknown_user_results_in_failure(okta_client, caplog):
    with pytest.raises(MFAAuthenticationFailure) as exc:
        okta_client.push_authenticate("unknown-user")

    assert "User unknown-user not found" in str(exc)
    assert "User unknown-user not found" in caplog.text


def test_authentication_with_invalid_response_results_in_failure(okta_client, okta_user, caplog):
    with pytest.raises(MFAAuthenticationFailure) as exc:
        okta_client.otp_authenticate(okta_user, "almafa")

    assert "OTP validation failure" in str(exc)
    assert "OTP validation failure" in caplog.text


def test_authentication_with_unknown_factor_results_in_failure(okta_client, okta_user):
    with pytest.raises(MFAAuthenticationFailure) as exc:
        okta_client.otp_authenticate(okta_user, "Q=invalidfactor")

    assert "Unknown factor type provided 'Q'" in str(exc)


def test_authentication_with_uninitialized_factor_results_in_failure(okta_client, okta_user):
    with pytest.raises(MFAAuthenticationFailure) as exc:
        okta_client.otp_authenticate(okta_user, "r=invalidresponse")

    assert "Selected factor 'RSA' not found for user" in str(exc)


def test_unreachable_url_results_in_service_unreachable(okta_client, inject_connection_error, caplog):

    with pytest.raises(MFAServiceUnreachable) as exc:
        okta_client.push_authenticate("unknown-user")

    assert "Okta is not reachable" in str(exc)
    assert "Okta access error" in caplog.text


@pytest.mark.interactive
def test_timed_out_push_is_considered_a_failure(okta_client, okta_user, caplog, interactive):

    message = "We are testing a timed out Okta authentication now, so please wait the push notification to expire"
    interactive.message(message)
    with pytest.raises(MFAAuthenticationFailure) as exc:
        okta_client.push_authenticate(okta_user)

    assert "Okta push notification timed out" in str(exc)
    assert "Okta push notification timed out" in caplog.text


@pytest.mark.interactive
def test_declined_push_response_is_considered_a_failure(okta_client, okta_user, caplog, interactive):

    interactive.message("We expect a declined Okta authentication now, so please Decline the push authentication")
    with pytest.raises(MFAAuthenticationFailure) as exc:
        okta_client.push_authenticate(okta_user)

    assert "Okta push notification verify failed" in str(exc)
    assert "Okta push notification verify failed" in caplog.text
