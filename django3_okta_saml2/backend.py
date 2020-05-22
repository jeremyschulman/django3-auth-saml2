from django.contrib.auth.backends import RemoteUserBackend


class SAML2RemoteUserBackend(RemoteUserBackend):

    def authenticate(self, request, remote_user):
        res = super(SAML2RemoteUserBackend, self).authenticate(request, remote_user)
        return res
