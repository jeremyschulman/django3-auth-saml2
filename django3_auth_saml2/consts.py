app_name = 'django3_okta_saml2'

DEFAULT_NEXT_URL = '/'

LABEL_SSO_ACS = "sso_acs"
LABEL_SSO_LOGIN = "sso_login"
LABEL_SSO_DENIED = "sso_denied"

VIEWNAME_SSO_ACS = f"{app_name}:{LABEL_SSO_ACS}"
VIEWNAME_SSO_LOGIN = f"{app_name}:{LABEL_SSO_LOGIN}"
VIEWNAME_SSO_DENIED = LABEL_SSO_DENIED