

from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity, NAMEID_FORMAT_EMAILADDRESS
)

from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

from django.conf import settings
from django.contrib.auth.models import Group
from django.contrib.auth import login, get_user_model
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseRedirect
from django.utils.http import is_safe_url
from django.urls import reverse
from django.utils.module_loading import import_string
from django.core.handlers.wsgi import WSGIRequest

from rest_auth.utils import jwt_encode


# default User or custom User. Now both will work.
User = get_user_model()


def _default_next_url():
    if 'DEFAULT_NEXT_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['DEFAULT_NEXT_URL']

    # Lazily evaluate this in case we don't have admin loaded.
    return reverse('admin:index')


def get_current_domain(req: WSGIRequest) -> str:

    if 'ASSERTION_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['ASSERTION_URL']

    return '{scheme}://{host}'.format(
        scheme='https' if req.is_secure() else 'http',
        host=req.get_host()
    )


def _get_metadata():

    if 'METADATA_LOCAL_FILE_PATH' in settings.SAML2_AUTH:
        return {
            'local': [settings.SAML2_AUTH['METADATA_LOCAL_FILE_PATH']]
        }

    return {
        'remote': [
            {
                "url": settings.SAML2_AUTH['METADATA_AUTO_CONF_URL']
            }
        ]
    }


def _get_saml_client(domain):
    acs_url = domain + reverse('django_saml2_auth:acs')
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

    if 'ENTITY_ID' in settings.SAML2_AUTH:
        saml_settings['entityid'] = settings.SAML2_AUTH['ENTITY_ID']

    if 'NAME_ID_FORMAT' in settings.SAML2_AUTH:
        service_sp_data["name_id_format"] = settings.SAML2_AUTH['NAME_ID_FORMAT']

    sp_config = Saml2Config()
    sp_config.load(saml_settings)
    sp_config.allow_unknown_attributes = True
    saml_client = Saml2Client(config=sp_config)

    return saml_client


def denied(req: WSGIRequest):
    return render(req, 'django_saml2_auth/denied.html')


def _create_new_user(user_name, email, first_name, last_name):
    user = User.objects.create_user(user_name, email)
    user.first_name = first_name
    user.last_name = last_name

    new_user_profile = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {})

    groups = [Group.objects.get(name=group_name)
              for group_name in new_user_profile.get('USER_GROUPS', [])]

    user.groups.set(groups)

    user.is_active = new_user_profile.get('ACTIVE_STATUS', True)
    user.is_staff = new_user_profile.get('STAFF_STATUS', True)
    user.is_superuser = new_user_profile.get('SUPERUSER_STATUS', False)
    user.save()

    return user


@csrf_exempt
def acs(req: WSGIRequest):
    """
    This endpoint is invoked by the SSO SAML system, for example Okta, when the User
    attempts to login via that SSO system.
    """

    if not req.session.session_key:
        session_key = req.POST.get('RelayState')
        req.session = req.session.__class__(session_key)

    next_url = req.session.get('login_next_url', _default_next_url())

    # obtain the results of the SSO signin process, and if there is no
    # 'SAMLResponse' found in the POST parameters, then it means that the User
    # attempted to access the Django app without first going through the SSO
    # system.

    saml_client = _get_saml_client(get_current_domain(req))
    resp = req.POST.get('SAMLResponse', None)
    if not resp:
        return HttpResponseRedirect(
            reverse('django_saml2_auth:denied')
        )

    # Validate the SSO response and obtain the User identity information. If
    # any part of this process fails, then redirect to a denied page.

    authn_response = saml_client.parse_authn_request_response(
        resp,
        entity.BINDING_HTTP_POST
    )

    if authn_response is None:
        return HttpResponseRedirect(
            reverse('django_saml2_auth:denied')
        )

    user_identity = authn_response.get_identity()
    if user_identity is None:
        return HttpResponseRedirect(
            reverse('django_saml2_auth:denied')
        )

    # SSO validation process is completed, so next step is to use the SSO
    # response payload about the User (identity) so that we can either obtain
    # an existing Django user record, create one if we should, or reject the
    # user if we should not.

    user_fields = dict()

    if authn_response.name_id.format == NAMEID_FORMAT_EMAILADDRESS:
        email = authn_response.name_id.text
        user_fields['email'] = email
        user_fields['first_name'] = 'Jeremy'
        user_fields['last_name'] = 'Schulman'
        user_fields['user_name'] = user_fields['email']

    # attr_map = settings.SAML2_AUTH.get('ATTRIBUTES_MAP')
    # attr_vals = {}
    # if attr_map:
    #
    #     user_email = user_identity.get(attr_map.get('email', 'Email'))
    # user_name = user_identity[attr_map.get('username', 'UserName')][0]
    # user_first_name = user_identity[attr_map.get('first_name', 'FirstName')][0]
    # user_last_name = user_identity[attr_map.get('last_name', 'LastName')][0]

    try:
        user_obj = User.objects.get(username=user_fields['user_name'])

    except User.DoesNotExist:
        user_obj = None

    if not user_obj:
        if not settings.SAML2_AUTH.get('CREATE_USER', True):
            return HttpResponseRedirect(
                reverse('django_saml2_auth:denied')
            )

        user_obj = _create_new_user(**user_fields)

        # If the app configured a trigger function to call after a new user is
        # created then execute that function now.
        # TODO: add a return code to indicate to proceed or abort/deny

        hook_create_user = settings.SAML2_AUTH.get('TRIGGER', {}).get('CREATE_USER', None)
        if hook_create_user:
            import_string(hook_create_user)(user_identity)

    req.session.flush()

    if not user_obj.is_active:
        return HttpResponseRedirect(
            reverse('django_saml2_auth:denied')
        )

    # -------------------------------------------------------------------------
    # !!!                         Login User                               !!!!
    # -------------------------------------------------------------------------

    user_obj.backend = 'django.contrib.auth.backends.ModelBackend'
    login(req, user_obj)

    if not settings.SAML2_AUTH.get('USE_JWT'):
        return HttpResponseRedirect(next_url)

    # We use JWT auth send token to frontend

    jwt_token = jwt_encode(user_obj)
    query = '?uid={}&token={}'.format(user_obj.id, jwt_token)

    frontend_url = settings.SAML2_AUTH.get(
        'FRONTEND_URL', next_url)

    return HttpResponseRedirect(frontend_url+query)


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

    url_ok = is_safe_url(next_url, None)
    if not url_ok:
        return HttpResponseRedirect(
            reverse('django_saml2_auth:denied')
        )

    # Store the next URL to goto into the User session area so that the the SSO
    # route ('acs') can use it once the User has completed the SSO process.

    req.session['login_next_url'] = next_url
    session_id = req.session.session_key

    # Next we need to obtain the SSO system URL to direct the User's browser to
    # that system so that they can perform the login.

    saml_client = _get_saml_client(get_current_domain(req))
    req_id, info = saml_client.prepare_for_authenticate()

    redirect_url = dict(info['headers'])['Location']

    # We need to pass the Django session key as the Okta RelayState
    # so that we can recover the session data later.  Alternatively we could
    # simply pass the login_next_url value and avoid sessions altogether.
    # TODO.

    redirect_url += f"&RelayState={session_id}"

    # This causes the web client to go to the SSO SAML system to force the use
    # to use that system to authenticate.

    return HttpResponseRedirect(redirect_url)
