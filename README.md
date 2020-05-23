# Okta SAML2 integration for Django3 Apps

This package is derviced from [django-saml2-auth](https://github.com/fangli/django-saml2-auth).
The updates are specific optimzations for:

   * Django3 framework
   * SAML 2.0
   * Provides only two views used for login and signon purposes
   * Uses Django RemoteUserBackend to handle User create & configuraiton
   
# System Requirements

This package requires the xmlsec library to be installed.
    
# Provided Views

This package provides two views:

   * `acs` - This URL View should be called by the SSO system (Okta)
   * `login` - The URL View should be called when the User attempts to login directly to the app
  
When the User attempts to use  `login`, the View will redirect the User's web
browser to the SSO system for authentication.  Once the User authenticates at
the SSO system, the SSO system will then call the `acs` URL view to sign into
the Django app.

# Supported Configuration Options

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
    path('sso/', include('django3_okta_saml2.urls')),
    path('login/', RedirectView.as_view(url='/sso/login/')),
]
```

# Using Netbox?

If you are using [Netbox](https://netbox.readthedocs.io/en/stable/) and you do
not want to fork/modify the system `settings.py` file, please refer to
[netbox-plugin-auth-saml2](https://github.com/jeremyschulman/netbox-plugin-auth-saml2)

   