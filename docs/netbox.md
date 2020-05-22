# Netbox 2.8 Integration HOWTO

Netbox 2.8 provides enhancements to support remote user authentication uses specific
variables defined in the configuration.py file, as described here:

https://netbox.readthedocs.io/en/stable/configuration/optional-settings/

    'AUTHENTICATION_BACKEND': 'utilities.auth_backends.RemoteUserBackend',