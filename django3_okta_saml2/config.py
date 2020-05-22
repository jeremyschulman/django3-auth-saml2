from django.conf import settings

if hasattr(settings, 'SAM2_AUTH_CONFIG'):
    SAML2_AUTH_CONFIG = settings.SAML2_AUTH
else:
    SAML2_AUTH_CONFIG = {}
