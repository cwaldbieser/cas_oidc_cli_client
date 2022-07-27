
CAS OIDC Client Utility
=======================

Acts as an OIDC client against an Apereo CAS OIDC provider.


Example:

.. code::sh

   $ ./oidc_client.py https://cas.stage.lafayette.edu/cas/oidc ./client_info.json frosta ./frosta.passwd

Client Configuration
--------------------

Client information is passed into the program as a path to a JSON file with the following format:

.. code::json

    {
        "client_id": "the-client-id",
        "client_secret": "some-secret-string-shared-with-the-oidc-provider",
        "redirect_uris": ["the-redirect-url"]
    }

