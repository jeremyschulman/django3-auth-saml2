app_name = 'django3_auth_saml2'

DEFAULT_NEXT_URL = '/'
DEFAULT_NAME_TO_ID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

LABEL_SSO_ACS = "sso_acs"
LABEL_SSO_LOGIN = "sso_login"

VIEWNAME_SSO_ACS = f"{app_name}:{LABEL_SSO_ACS}"
