from django.conf import settings

try:
    SAML2_AUTH_CONFIG = settings.SAML2_AUTH_CONFIG

except:
    SAML2_AUTH_CONFIG = {}
