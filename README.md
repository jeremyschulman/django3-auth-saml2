# Okta SAML2 integration for Django3 Apps

This package is derviced from [django-saml2-auth](https://github.com/fangli/django-saml2-auth).
The updates are specific optimzations for:

   * Django3 framework
   * SAML 2.0
   * Provides only two views used for login and signon purposes
   * Uses Django RemoteUserBackend to handle User create & configuraiton
   
# Supported Options

In the Django `settings.py` file you must define the `SAML2_AUTH` configuraiton
dictionary.  The options have been streamlined from the original
django-sam2-auth package, only the following are supported:

   * **AUTHENTICATION_BACKEND** - (NEW) the dotted string name of the backend
   * **METADATA_LOCAL_FILE_PATH** - same
   * **METADATA_AUTO_CONF_URL** - same
   * **ENTITY_ID** - same
   * **ASSERTION_URL** - same
   * **NAME_ID_FORMAT** - same

By default the User name value will be taken from the SAML response name_id.text value.

Example for using Netbox

````python

SAML2_AUTH = {
    # Django authentication backend, must be a subclass of RemoteUserBackend
    # REQUIRED
    
    # Using Netbox default remote backend
    'AUTHENTICATION_BACKEND': 'utilities.auth_backends.RemoteUserBackend',

    # Metadata is required, choose either remote url or local file path
    'METADATA_LOCAL_FILE_PATH': '/etc/oktapreview-netbox-metadata.xml',

    # Setting in Okta Admin for this App

    'ENTITY_ID': 'https://okta-devtest.ngrok.io',
    'ASSERTION_URL': 'https://okta-devtest.ngrok.io',
    'NAME_ID_FORMAT': "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",

}
````

   
 
