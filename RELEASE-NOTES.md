# Release Notes

#### v0.2.0 (2020-Jun-19)
   * Added `SSO_ACS_URL` to configuration to dynamically set the URL that
   will be used for SSO sign-in; previously was hardcoded to use
   a reverse-loopup technique based on this package-name.  Defaults
   to `/sso/acs`.
   * Added logging to `views.py` file.