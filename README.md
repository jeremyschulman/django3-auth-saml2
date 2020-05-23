# Django3 auth SAML2 integration

As a developer of Django3 applications I need to integrate Single-Sign-On (SSO)
User authentication using SAML2,for example with Okta.  I know there are a
number of existing packages out there, but I want something super-simple that
does not require a lot of configuration in my `settings.py` file.  I also need
this integration to work with exsitng Django solutions that _do not allow me to
modify settings.py directly_, as is the case with
[Netbox](https://github.com/netbox-community/netbox).

This `django3_auth_saml2` package was inspired by the existing
[django-saml2-auth](https://github.com/fangli/django-saml2-auth).  

Changes provided in `django3_auth_saml2`:

   1. Django3 / Python3 code base
   1. Provides two Views: one for the login redirect to the SSO and the other for the SSO signin
   1. Uses Django RemoteUserBackend (or subclass) to handle User creation and configuration process
   1. Provide the SAML2 authenticate response payload in `response.META['SAML2_AUTH_RESPONSE']`
   1. Any errors result in `PermissionDenied` exceptions to allow for app specific handling

## System Requirements

This package requires the `xmlsec` library to be installed.
    
## Views

This package provides two views:

   * `acs` - This URL View should be called by the SSO system (Okta)
   * `login` - The URL View should be called when the User attempts to login directly to the app
  
When the User attempts to use  `login`, the View will redirect the User's web
browser to the SSO system for authentication.  Once the User authenticates at
the SSO system, the SSO system will then call the `acs` URL view to sign into
the Django app.

## Django System Configuration

The options have been streamlined from the original django-sam2-auth package,
only the following are supported:

**REQUIRED**
   * **AUTHENTICATION_BACKEND** - (NEW) the dotted string name of the backend
   
   One of:   
   * **METADATA_LOCAL_FILE_PATH** - same
   * **METADATA_AUTO_CONF_URL** - same
   
*OPTIONAL*      
   * **ENTITY_ID** - same
   * **ASSERTION_URL** - same
   * **NAME_ID_FORMAT** - same

By default the User name value will be taken from the SAML response
`name_id.text` value.  For example, if the NAME_ID_FORMAT is set to use email,
then the User name value will be the User's email address.

You should create the `SAM2_AUTH_CONFIG` dictionary in the Django `settings.py` file,
for example:

````python
SAML2_AUTH_CONFIG = {
    # Django authentication backend, must be a subclass of RemoteUserBackend
    
    # Using Netbox default remote backend
    'AUTHENTICATION_BACKEND': 'django.contrib.auth.backends.RemoteUserBackend',

    # Metadata is required, choose either remote url or local file path
    'METADATA_LOCAL_FILE_PATH': '/etc/oktapreview-netbox-metadata.xml',

    # Setting in Okta Admin for this App

    # Use email as the User name
    'NAME_ID_FORMAT': "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
}
````

# Setting up URLs

In your ROOT_URLCONF.urlpatterns you will need to define to URLs.  The first is
for the SSO system, and the second is your login URL that will force the User
to authenticate via the SSO first.  You can change these to suit your specific
app API.  Keep in mind that the 'django3_okta_saml2.urls' provides the 'acs'
view, so that the example below would result in the app API "sso/acs/".

```python

urlpatterns = [
    path('sso/', include('django3_auth_saml2.urls')),
    path('login/', RedirectView.as_view(url='/sso/login/')),
]
```

## RemoteUserBackend

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
`configure_user()` methods to use the response.META['SAML2_AUTH_RESPONSE'] data. 
You can to access the SAML2 user identiy attributes:

```python
user_identity = saml2_auth_resp.get_identity()
```

The `user_identity` return value is a dictionary of the key-value pairs
as assigned in the SSO system.


# Using Netbox?

If you are using [Netbox](https://netbox.readthedocs.io/en/stable/) and you do
not want to fork/modify the system `settings.py` file, please refer to
[netbox-plugin-auth-saml2](https://github.com/jeremyschulman/netbox-plugin-auth-saml2)

   