
CAS OIDC Client Utility
=======================

Acts as an OIDC client against an Apereo CAS OIDC provider.


Example::

    $ ./oidc_client.py https://cas.example.net/cas/oidc ./client_info.json jamesbond ./007.passwd

Client Configuration
--------------------

Client information is passed into the program as a path to a JSON file with the following format::


    {
        "client_id": "the-client-id",
        "client_secret": "some-secret-string-shared-with-the-oidc-provider",
        "redirect_uris": ["the-redirect-url"]
    }

