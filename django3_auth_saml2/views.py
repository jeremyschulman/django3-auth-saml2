
# -----------------------------------------------------------------------------
# System Imports
# -----------------------------------------------------------------------------

from functools import lru_cache

# -----------------------------------------------------------------------------
# Public Imports
# -----------------------------------------------------------------------------

from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity,
    SAMLError
)

from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

from django.contrib.auth import login, load_backend
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseRedirect
from django.utils.http import is_safe_url
from django.urls import reverse
from django.core.handlers.wsgi import WSGIRequest
from django.core.exceptions import PermissionDenied

# -----------------------------------------------------------------------------
# Private Imports
# -----------------------------------------------------------------------------


from . import consts
from . config import SAML2_AUTH_CONFIG

# #############################################################################
#
#                                CODE BEGINS
#
#
# #############################################################################


# -----------------------------------------------------------------------------
#
#                                   Views
#
# -----------------------------------------------------------------------------

@csrf_exempt
def sso_acs(req: WSGIRequest) -> HttpResponseRedirect:
    """
    This endpoint is invoked by the SSO SAML system, for example Okta, when the User
    attempts to login via that SSO system.
    """
    next_url = req.POST.get('RelayState') or _default_next_url()

    # obtain the results of the SSO signin process, and if there is no
    # 'SAMLResponse' found in the POST parameters, then it means that the User
    # attempted to access the Django app without first going through the SSO
    # system.

    saml_client = _get_saml_client(req)
    resp = req.POST.get('SAMLResponse', None)
    if not resp:
        raise PermissionDenied("SAML2: missing response")

    # Validate the SSO response and obtain the User identity information. If
    # any part of this process fails, then redirect to a denied page.

    try:
        authn_response = saml_client.parse_authn_request_response(
            resp,
            entity.BINDING_HTTP_POST
        )

        if authn_response is None:
            raise PermissionDenied("SAML2: failed to parse response")

        user_identity = authn_response.get_identity()
        if user_identity is None:
            raise PermissionDenied("SAML2: no identity")

    except SAMLError as exc:
        raise PermissionDenied(f"SAML2 error: {str(exc)}")

    # SSO validation process is completed, so next step is to use the SSO
    # response payload about the User (identity) so that we can either obtain
    # an existing Django user record, create one if we should, or reject the
    # user if we should not.

    user_name = authn_response.name_id.text
    backend_name = SAML2_AUTH_CONFIG['AUTHENTICATION_BACKEND']
    backend_obj = load_backend(backend_name)

    # the call to authenticate will call the configure_user method if it
    # exists; the backend is responsible for implementing the necessary
    # configuration options.

    user_obj = backend_obj.authenticate(req, user_name)
    if not user_obj:
        raise PermissionDenied(f"SAML2: no-authenticate user {user_name}")

    # Login user and redirect to the "next URL"

    user_obj.backend = backend_name
    login(req, user_obj)
    return HttpResponseRedirect(next_url)


def signin(req: WSGIRequest) -> HttpResponseRedirect:
    """
    This route is invoked when the User attempts to login to the application
    without first going through the SSO SAML system.  As a result of executing
    this function the User's browswer should be redirected to the SSO system.
    """

    # obtain the 'next' parameter from the GET command, and if not provided,
    # then use the default value as configured in the settings.

    next_url = req.GET.get('next', _default_next_url())

    # Only permit signin requests where the next_url is a safe URL

    if not is_safe_url(next_url, None):
        raise PermissionDenied(f"SAML2: unsafe next URL: {next_url}")

    # Next we need to obtain the SSO system URL to direct the User's browser to
    # that system so that they can perform the login.  We use the RelayState
    # URL parameter to pass the 'next-url' value back to the sso handler.

    saml_client = _get_saml_client(req)
    req_id, info = saml_client.prepare_for_authenticate()

    redirect_url = dict(info['headers'])['Location']
    redirect_url += f"&RelayState={next_url}"

    # This causes the web client to go to the SSO SAML system to force the use
    # to use that system to authenticate.

    return HttpResponseRedirect(redirect_url)


# -----------------------------------------------------------------------------
#
#                          Private Helper Functions
#
# -----------------------------------------------------------------------------

@lru_cache()
def _default_next_url():
    if 'DEFAULT_NEXT_URL' in SAML2_AUTH_CONFIG:
        return SAML2_AUTH_CONFIG['DEFAULT_NEXT_URL']

    return consts.DEFAULT_NEXT_URL


@lru_cache()
def get_current_domain(req: WSGIRequest) -> str:
    if 'ASSERTION_URL' in SAML2_AUTH_CONFIG:
        return SAML2_AUTH_CONFIG['ASSERTION_URL']

    return '{scheme}://{host}'.format(
        scheme='https' if req.is_secure() else 'http',
        host=req.get_host()
    )


def _get_metadata():
    if 'METADATA_LOCAL_FILE_PATH' in SAML2_AUTH_CONFIG:
        return {
            'local': [SAML2_AUTH_CONFIG['METADATA_LOCAL_FILE_PATH']]
        }

    return {
        'remote': [
            {
                "url": SAML2_AUTH_CONFIG['METADATA_AUTO_CONF_URL']
            }
        ]
    }


def _get_saml_client_config(domain):
    acs_url = domain + reverse(consts.VIEWNAME_SSO_ACS)
    metadata = _get_metadata()

    service_sp_data = {
        'endpoints': {
            'assertion_consumer_service': [
                (acs_url, BINDING_HTTP_REDIRECT),
                (acs_url, BINDING_HTTP_POST)
            ],
        },
        'allow_unsolicited': True,
        'authn_requests_signed': False,
        'logout_requests_signed': True,
        'want_assertions_signed': True,
        'want_response_signed': False
    }

    saml_settings = {
        'metadata': metadata,
        'service': {'sp': service_sp_data},
    }

    if 'ENTITY_ID' in SAML2_AUTH_CONFIG:
        saml_settings['entityid'] = SAML2_AUTH_CONFIG['ENTITY_ID']

    if 'NAME_ID_FORMAT' in SAML2_AUTH_CONFIG:
        service_sp_data["name_id_format"] = SAML2_AUTH_CONFIG['NAME_ID_FORMAT']

    sp_config = Saml2Config()
    sp_config.load(saml_settings)
    sp_config.allow_unknown_attributes = True


def _get_saml_client(req):
    domain = get_current_domain(req)
    return Saml2Client(config=_get_saml_client_config(domain))
