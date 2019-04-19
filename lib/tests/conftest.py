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

import logging
import pytest

logger = logging.getLogger("spsokta_conftest")


@pytest.fixture
def okta_api_url(site_parameters):
    return site_parameters['api_url']


@pytest.fixture
def okta_api_key(site_parameters):
    return site_parameters['api_key']


@pytest.fixture
def okta_application_id(site_parameters):
    return site_parameters['application_id']


@pytest.fixture
def okta_user(site_parameters):
    return site_parameters['username']


@pytest.fixture
def plugin_config(okta_api_url, okta_api_key, okta_application_id):
    return """
[okta]
api_url={api_url}
api_key={api_key}
application_id={application_id}
defaultOTPtype=o

[auth]
prompt=Hit Enter to send Okta Verify push notification or provide the OTP:
""".format(api_url=okta_api_url, api_key=okta_api_key, application_id=okta_application_id)


last_totp = None


@pytest.fixture
def totp_response(request, site_parameters):
    import pyotp
    import time

    def get_next_totp():
        global last_totp

        # this loop makes sure that the OTP is changed between testcases by
        # waiting enough time for the OTP to change

        logger.info("Wait until new OTP is generated")

        while True:
            current_totp = pyotp.TOTP(site_parameters['totp_secret']).now()
            if current_totp != last_totp:
                last_totp = current_totp
                return 'g=' + current_totp
            time.sleep(1)

    backend_service = request.config.getoption('backend_service')
    if backend_service == 'replay':
        return lambda: 'g=' + pyotp.TOTP(site_parameters['totp_secret']).now()
    else:
        return get_next_totp
