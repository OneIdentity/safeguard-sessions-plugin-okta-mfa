#
#   Copyright (c) 2019 One Identity
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
from safeguard.sessions.plugin.mfa_client import (
    MFAClient,
    MFAAuthenticationFailure,
    MFACommunicationError,
    MFAServiceUnreachable,
)
from requests import RequestException, request
from urllib.parse import urljoin
import json
import re
import logging
import time

FACTOR_TYPE = {
    "g": {"provider": "GOOGLE", "type": "token:software:totp"},
    "o": {"provider": "OKTA", "type": "token:software:totp"},
    "p": {"provider": "OKTA", "type": "push"},
    "s": {"provider": "SYMANTEC", "type": "token"},
    "y": {"provider": "YUBICO", "type": "token:hardware"},
    "r": {"provider": "RSA", "type": "token"},
}


class Client(MFAClient):
    """Simple Okta library which can do basic one-time-password auth and push notification
    """

    def __init__(
        self,
        api_url,
        application_id,
        api_key,
        timeout=30,
        httptimeout=15,
        pollinterval=1,
        defaultOTPtype="o",
        ignore_connection_error=False,
    ):
        super().__init__("SPS Okta plugin", ignore_connection_error)
        self.baseuri = api_url if api_url and api_url[-1] == "/" else api_url + "/"
        self.timeout = timeout
        self.httptimeout = httptimeout
        self.pollinterval = pollinterval
        self.defaultOTPtype = defaultOTPtype
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": application_id,
            "Authorization": "SSWS " + api_key,
        }
        self.user = None
        self.provider = None
        self.factor = None
        self.passcode = None
        self.logger = logging.getLogger(__name__)

    @classmethod
    def from_config(cls, plugin_configuration, section="okta"):
        return cls(
            plugin_configuration.get(section, "api_url", required=True),
            plugin_configuration.get(section, "application_id", "SPSOktaMFA/2.0"),
            plugin_configuration.get(section, "api_key", required=True),
            timeout=plugin_configuration.getint(section, "timeout", 60),
            httptimeout=plugin_configuration.getint(section, "http_socket_timeout", 15),
            pollinterval=plugin_configuration.getint(section, "rest_poll_interval", 1),
            defaultOTPtype=plugin_configuration.get(section, "default_prefix", "o"),
            ignore_connection_error=plugin_configuration.getboolean(section, "ignore_connection_error"),
        )

    def otp_authenticate(self, user, passcode):
        return self.do_authentication(user, passcode)

    def push_authenticate(self, user):
        return self.do_authentication(user)

    def do_authentication(self, user, passcode=""):
        try:
            self._authenticate(user, passcode)
        except OktaHttpError as err:
            if err.response.status_code >= 500:
                self.logger.error("Okta access error: %s", err.response)
                raise MFAServiceUnreachable("Okta is not reachable")
            else:
                self.logger.error("Unexpected error returned by Okta %s", err.response)
                raise MFACommunicationError("Unexpected error returned by Okta %s", err.response)
        except RequestException as err:
            self.logger.error("Okta access error: %s", err)
            raise MFAServiceUnreachable("Okta is not reachable")

        return True

    def _authenticate(self, user, passcode=""):
        # Find the user in OKTA
        self._find_user(user)
        self._find_provider(passcode)
        self._find_factor()

        # If the factor is token based then check the given passcode
        # otherwise try the PUSH method
        if self.factor["factorType"][0:5] == "token":
            self.logger.debug("Checking factor for OTP")
            self.check_otp(self.passcode)
        elif self.factor["factorType"] == "push":
            self.logger.debug("Checking factor for PUSH")
            self.check_push()
        else:
            raise MFAAuthenticationFailure("Don't know how to authenticate using {}".format(self.factor["factorType"]))

    def _find_user(self, username):
        try:
            self.user = self._query("users/{}".format(username))
        except OktaHttpError as exc:
            if exc.response.status_code == 404:
                self.logger.error("User %s not found", username)
                raise MFAAuthenticationFailure("User {} not found".format(username))
            else:
                raise

        self.logger.debug(
            "User '%s' found: login='%s'; email='%s'",
            username,
            self.user["profile"]["login"],
            self.user["profile"]["email"],
        )

    def _find_provider(self, passcode):
        (provider, passcode) = self._extract_provider_from_passcode(passcode)
        self.provider = FACTOR_TYPE[provider]
        self.passcode = passcode

        self.logger.info("Selected provider: [%s/%s/%s]", provider, self.provider["provider"], self.provider["type"])

    def _extract_provider_from_passcode(self, passcode):
        # If no passcode, then try OKTA PUSH
        if not passcode or passcode == "":
            provider = "p"
            self.logger.debug("There is no passcode, using push method")
        else:
            if passcode and re.match(r"^\w[=~_].*$", passcode):
                (provider, passcode) = re.split("=|~|_", passcode)
                self.logger.debug("Processed OTP and extracted provider and passcode: %s, %s", provider, passcode)
            else:
                provider = self.defaultOTPtype
                self.logger.info("Passcode did not have a provider prefix, using default provider: %s", provider)

        if provider not in FACTOR_TYPE:
            raise MFAAuthenticationFailure("Unknown factor type provided '{}'".format(provider))

        return (provider, passcode)

    def _find_factor(self):
        factors = self._query("users/{}/factors".format(self.user["id"]))
        if isinstance(factors, list):
            for factor in factors:
                if "id" not in factor:
                    break
                self.logger.debug(
                    "Checking factor (%s; %s; %s)",
                    factor.get("provider"),
                    factor.get("factorType"),
                    factor.get("status"),
                )
                if (
                    factor.get("provider") == self.provider["provider"]
                    and factor.get("factorType") == self.provider["type"]
                    and factor.get("status") == "ACTIVE"
                ):
                    self.factor = factor
                    return True
        raise MFAAuthenticationFailure("Selected factor '{}' not found for user".format(self.provider["provider"]))

    def check_push(self):
        verify_response = self._query(self._get_factor_verify_url(self.factor), "", expected_status=201)
        poll_url = self._get_verify_response_poll_url(verify_response)

        endtime = time.time() + self.timeout
        count = 0
        while time.time() < endtime:
            count = count + 1
            self.logger.debug("Polling Okta, attempt: %d, still %lf seconds to go", count, endtime - time.time())
            result = self._query(poll_url)
            factor_result = result.get("factorResult")
            if factor_result == "SUCCESS":
                self.logger.info("Okta push notification verify succeeded. Status: %s", factor_result)
                return
            elif factor_result == "WAITING":
                self.logger.debug("Okta push notification is awaiting user approval. Status: %s", factor_result)
                time.sleep(self.pollinterval)
                continue
            else:
                self.logger.error("Okta push notification verify failed. Status: %s", factor_result)
                raise MFAAuthenticationFailure("Okta push notification verify failed, result: {}".format(factor_result))
        self.logger.error("Okta push notification timed out")
        raise MFAAuthenticationFailure("Okta push notification timed out")

    def check_otp(self, otp):
        self.logger.info("Checking OTP: %s", otp)
        try:
            result = self._query(self.factor["_links"]["verify"]["href"], data=json.dumps({"passCode": otp}))
        except OktaHttpError as exc:
            if exc.response.status_code < 500:
                error = exc.response.json()
                self.logger.error(
                    "OTP validation failure: {errorSummary} (code: {errorCode}, id: {errorId})".format(**error)
                )
                raise MFAAuthenticationFailure(
                    "OTP validation failure: {errorSummary}" " (code: {errorCode}, id: {errorId})".format(**error)
                )
            else:
                raise

        factor_result = result.get("factorResult")
        self.logger.debug("Result: %s", result)
        if factor_result != "SUCCESS":
            raise MFAAuthenticationFailure(
                "Okta returned {} in response to our one time password.".format(factor_result)
            )

    @staticmethod
    def _get_factor_verify_url(factor):
        try:
            return factor["_links"]["verify"]["href"]
        except KeyError:
            raise MFACommunicationError("factor does not contain the verify URL: >>{}<<".format(factor))

    @staticmethod
    def _get_verify_response_poll_url(verify_response):
        try:
            return verify_response["_links"]["poll"]["href"]
        except KeyError:
            raise MFACommunicationError("verify response does not contain the poll URL: >>{}<<".format(verify_response))

    def _query(self, url, data=None, expected_status=200):
        if not re.match("^https://", url.lower()):
            url = urljoin(self.baseuri, url)
        self.logger.debug("Sending request: %s, [%s]", url, data)
        response = request(
            url=url,
            data=data,
            headers=self.headers,
            method="GET" if data is None else "POST",
            timeout=self.httptimeout,
            verify=True,
        )
        self.logger.debug("Received response: %d, %s", response.status_code, response.text)
        try:
            if response.status_code == expected_status:
                return response.json()
            else:
                raise OktaHttpError(response=response)
        except ValueError:
            raise MFACommunicationError(
                "Error decoding JSON payload in response to {}, with response code {}".format(url, response.status_code)
            )


class OktaHttpError(Exception):
    def __init__(self, response):
        self.response = response
