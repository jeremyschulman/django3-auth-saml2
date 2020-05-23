# Django3 Auth SAML2 Integration

As a developer of Django3 applications I need to integrate a SAML2 based
Single-Sign-On (SSO) User authentication system, for example with
[Okta](https://www.okta.com/).  I know there are a number of existing packages
out there, but I want something super-simple that does not require a lot of
configuration in my `settings.py` file.  I also need this integration to work
with exsitng Django solutions that _do not allow me to modify settings.py
directly_, as is the case with
[Netbox](https://github.com/netbox-community/netbox).

This `django3_auth_saml2` package was inspired by the existing
[django-saml2-auth](https://github.com/fangli/django-saml2-auth).  

**Notable Changes**:

   1. Django3 / Python3 code base
   1. Provides two Views: one for the login redirect to the SSO and the other for the SSO signin
   1. Uses Django RemoteUserBackend (or subclass) to handle User creation and configuration process
   1. Provide the SAML2 authenticate response payload in `response.META['SAML2_AUTH_RESPONSE']`
   1. Any errors result in `PermissionDenied` exceptions to allow for app specific handling
   1. Configuration can be store in `django3_auth_saml2.config.SAML2_AUTH_CONFIG` as an alternative
   to using the Django `settings.py` file

## System Requirements

This package requires the `xmlsec` library to be installed.
    
## Views

This package provides two views:

   * `login` - The URL View should be called when the User attempts to login directly to the app
   * `acs` - This URL View should be called by the SSO system (Okta)
  
When the User attempts to use `login`, the View will redirect the User's web
browser to the SSO system for authentication.  Once the User authenticates at
the SSO system, the SSO system will then call the `acs` URL view to sign into
the Django app.

In your ROOT_URLCONF.urlpatterns you will need to define two URLs.  The first
is for the SSO system, and the second is your login URL that will force the
User to authenticate via the SSO first.  You can change these to suit your
specific app API.

Keep in mind that the 'django3_auth_saml2.urls' provides the 'acs' view, so
that the example below would result in the app API "/sso/acs/" and "/sso/login/".

```python

urlpatterns = [
    path('sso/', include('django3_auth_saml2.urls')),
    path('login/', RedirectView.as_view(url='/sso/login/')),
]
```

## Django System Configuration

The options have been streamlined from the original django-sam2-auth package,
only the following are supported:

### Required

**AUTHENTICATION_BACKEND**<br/>
(NEW) the dotted string name of the backend, for example:<br/>
"django.contrib.auth.backends.RemoteUserBackend"
   
One of:   

A) **METADATA_AUTO_CONF_URL**<br/>
The URL to the SSO system where the metadata document can be retrieved, for example:<br/>
"https://mycorp.oktapreview.com/app/sadjfalkdsflkads/sso/saml/metadata"

B) **METADATA_LOCAL_FILE_PATH**<br/>
As an alternative to using the URL, you can store the metadata contents to a local file, for example:<br/>
"/etc/oktapreview-netbox-metadata.xml" 

### Optional

**DEFAULT_NEXT_URL**<br/>
The next URL used to redirect the User after login is successful.  Defaults to "/".  

**ENTITY_ID**<br/>
This is generally the URL to your application, for example:<br/>
"https://okta-devtest.ngrok.io"<br/>

**ASSERTION_URL** - same
This is generally the URL to your application, for example:<br/>
"https://okta-devtest.ngrok.io"<br/>

**NAME_ID_FORMAT**<br/>
Identifies the format of the User name, see [docs](https://docs.oracle.com/cd/E19316-01/820-3886/ggwbz/index.html) for options.
This value defaults to using email.

By default the User name value will be taken from the SAML response
`name_id.text` value.  For example, if the NAME_ID_FORMAT is set to use email,
then the User name value will be the User's email address.

For more information on these terms, refer to [docs](https://support.okta.com/help/s/article/Common-SAML-Terms).

### Example

You should create the `SAML2_AUTH_CONFIG` dictionary in the Django `settings.py` file,
for example:

````python
SAML2_AUTH_CONFIG = {
    # Using default remote backend
    'AUTHENTICATION_BACKEND': 'django.contrib.auth.backends.RemoteUserBackend',

    # Metadata is required, choose either remote url or local file path
    'METADATA_AUTO_CONF_URL': "https://mycorp.oktapreview.com/app/sadjfalkdsflkads/sso/saml/metadata"
}
````

## User Create & Configuration via RemoteUserBackend

By default `acs` will define the `remote_user` parameter from the
`saml2_auth_resp.name_id.text` value when it calls the backend `authenticate()`
method.  For example, if the SSO system (Okta) has configured the name ID
format as email (as shown in the example above), then the User name will be the
Users email address.

The `acs` View will set the `response.META['SAML2_AUTH_RESPONSE']` to the
`saml2.response.AuthnResponse` instance so that you can access this
information.

When `acs` calls the backend `authenticate()`, the User will be created if it
does not exist by defaul; see class property `create_unknown_user`.  In this
case the `RemoteUserBackend.configure_user()` method is called.  

You can subclass RemoteUserBackend, implemeting your own `authenticate()` and
`configure_user()` methods to use the `response.META['SAML2_AUTH_RESPONSE']` data. 
You can to access the SAML2 user identiy attributes:

```python
saml2_uath_resp = response.META['SAML2_AUTH_RESPONSE']
user_identity = saml2_auth_resp.get_identity()
```

The `user_identity` return value is a dictionary of the key-value pairs
as assigned in the SSO system.

# Using Netbox?

If you are using [Netbox](https://netbox.readthedocs.io/en/stable/) and you do
not want to fork/modify the system `settings.py` file, please refer to
[netbox-plugin-auth-saml2](https://github.com/jeremyschulman/netbox-plugin-auth-saml2)

   