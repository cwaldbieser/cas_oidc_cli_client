#! /usr/bin/env python

import argparse
import getpass
import json
import logging
import pprint
import re
import sys
from urllib.parse import urlparse, urlunparse

# from oic.utils.http_util import Redirect
import requests
from bs4 import BeautifulSoup
from oic import rndstr
from oic.oic import Client
# from oic.oic.message import (AccessTokenResponse, AuthorizationResponse,
#                              RegistrationResponse)
from oic.oic.message import (AccessTokenResponse, AuthorizationResponse,
                             RegistrationResponse)
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

execution_pat = re.compile(r'<input type="hidden" name="execution" value="([^"]+)"')
eventid_pat = re.compile(r'<input type="hidden" name="_eventId" value="([^"]+)"')


def main(args):
    """
    Main program entry point.
    """
    set_log_level(args.log_level)
    verify = not args.no_verify
    user = args.user
    auth_req, client, info, session, client_args = create_oidc_client(
        args.scope, args.issuer, verify
    )
    login_url = auth_req.request(client.authorization_endpoint)
    print("Login url:", login_url)
    print("")
    if args.passwd_file is not None:
        passwd = args.passwd_file.read().rstrip()
    else:
        passwd = getpass.getpass()
    client_url_with_auth_code = perform_cas_authentication(
        login_url,
        verify,
        user,
        passwd,
        show_headers=args.show_headers,
        approval_prompt=args.approval_prompt,
        show_tgc=args.show_tgc,
    )
    p = urlparse(client_url_with_auth_code)
    query_string = p.query
    aresp = client.parse_response(
        AuthorizationResponse, info=query_string, sformat="urlencoded"
    )
    print("Authorization response parsed!")
    print("")
    code = aresp["code"]
    assert aresp["state"] == session["state"]
    client_args = {"code": code}
    print(f"code: {code}, state: {aresp['state']}")
    resp = client.do_access_token_request(
        state=aresp["state"],
        request_args=client_args,
        authn_method="client_secret_basic",
    )
    print("Access token request has been filled.")
    print("")
    if type(resp) != AccessTokenResponse:
        print("No access token!")
        sys.exit(1)
    id_token = resp["id_token"]
    print("= ID token =")
    pprint.pprint(id_token.to_dict())
    print("")
    access_token = aresp["state"]
    if args.show_access_token:
        print("Access token:", access_token)
        print("")
    userinfo = client.do_user_info_request(
        state=access_token,
    )
    print("= UserInfo endpoint data =")
    pprint.pprint(dict(userinfo))


def set_log_level(level_str):
    log_level = getattr(logging, level_str)
    logging.basicConfig(level=log_level)


def perform_cas_authentication(
    login_url,
    verify,
    user,
    passwd,
    show_headers=False,
    approval_prompt=False,
    show_tgc=False,
):
    """
    Perform the CAS authentication flow to obtain a CAS session (TGC).
    """
    with requests.Session() as s:
        response = s.get(login_url, verify=verify)
        if show_headers:
            print_headers(response)
        content = response.text
        cas_login_url = response.url
        print("CAS Login url:", cas_login_url)
        print("")
        cas_prefix = get_cas_endpoint_prefix(cas_login_url)
        m = execution_pat.search(content)
        if m is None:
            print("ERROR: Could not get execution!", file=sys.stderr)
            print(content, file=sys.stderr)
            sys.exit(1)
        execution = m.groups()[0]
        m = eventid_pat.search(content)
        if m is None:
            print("ERROR: Could not get _eventId", file=sys.stderr)
            sys.exit(1)
        event_id = m.groups()[0]
        data = {
            "username": user,
            "password": passwd,
            "execution": execution,
            "_eventId": event_id,
            "geolocation": "",
        }
        allow_redirects = approval_prompt
        response = s.post(
            cas_login_url, data=data, verify=verify, allow_redirects=allow_redirects
        )
        if show_headers:
            print_headers(response)
        if "TGC" not in s.cookies.keys():
            print("ERROR: Could not get TGC!", file=sys.stderr)
            sys.exit(1)
        tgc = s.cookies["TGC"]
        if show_tgc:
            print("TGC:", tgc)
            print("")
        if not approval_prompt:
            url = response.headers["Location"]
            while response.status_code == 302 and url.startswith(cas_prefix):
                print("Redirecting to: {}".format(url))
                response = s.get(url, allow_redirects=False)
                if show_headers:
                    print_headers(response)
                url = response.headers["Location"]
            client_url_with_auth_code = url
        else:
            # Next step is to parse response text HTML, get A tag with ID "allow".
            # HREF attribute is the link back to the client with the authorization
            # code.
            html_doc = response.text
            soup = BeautifulSoup(html_doc, "html.parser")
            allow_tag = soup.find(id="allow")
            link = allow_tag.get("href")
            print("allow link:", link)
            print("")
            response = s.get(link, verify=verify, allow_redirects=False)
            if show_headers:
                print_headers(response)
            client_url_with_auth_code = response.headers["Location"]
        print("Client URL with authorization code:", client_url_with_auth_code)
        print("")
    return client_url_with_auth_code


def create_oidc_client(scope, issuer, verify):
    """
    Initialize the OIDC client.
    """
    client = Client(client_authn_method=CLIENT_AUTHN_METHOD, verify_ssl=verify)
    info = json.load(args.client_info)
    client_reg = RegistrationResponse(**info)
    client.store_registration_info(client_reg)
    client.provider_config(args.issuer)
    # Copy the keyjar entry for the issuer (url) to the client_id.
    client.keyjar[info["client_id"]] = client.keyjar[issuer]
    session = {}
    session["state"] = rndstr()
    session["nonce"] = rndstr()
    requested_scopes = ["openid", "email", "profile"]
    if scope is not None:
        requested_scopes.extend(scope)
    client_args = {
        "client_id": client.client_id,
        "nonce": session["nonce"],
        "redirect_uri": client.registration_response["redirect_uris"][0],
        "response_type": "code",
        "scope": requested_scopes,
        "state": session["state"],
    }
    auth_req = client.construct_AuthorizationRequest(request_args=client_args)
    return auth_req, client, info, session, client_args


def print_headers(r):
    print("- Response Headers -", file=sys.stdout)
    for k, v in r.headers.items():
        print("  {}: {}".format(k, v), file=sys.stdout)
    print("status code:", r.status_code)
    print("")


def get_cas_endpoint_prefix(cas_login_url):
    """
    Get the CAS URL prefix.
    E.g. https://cas.example.net/cas
    """
    p = urlparse(cas_login_url)
    scheme, netloc, path, junk1, junk2, junk3 = p
    path_parts = path.split("/")
    prefix_path = "/".join(path_parts[:-1])
    prefix = urlunparse((scheme, netloc, prefix_path, "", "", ""))
    return prefix


if __name__ == "__main__":
    parser = argparse.ArgumentParser("OpenID Connect Client")
    parser.add_argument("issuer", action="store", help="The OIDC issuer URL.")
    parser.add_argument(
        "client_info",
        type=argparse.FileType("r"),
        action="store",
        help="JSON file containing `client_id` and `client_secret`.",
    )
    parser.add_argument("user", action="store", help="The user to log in as.")
    parser.add_argument(
        "passwd_file",
        type=argparse.FileType("r"),
        action="store",
        help="A file containing the user password.",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable TLS verification for the OIDC provider URLs.",
    )
    parser.add_argument(
        "--approval-prompt",
        action="store_true",
        help="Activate if the OIDC flow includes an approval step.",
    )
    parser.add_argument(
        "--show-headers", action="store_true", help="Show HTTP headers."
    )
    parser.add_argument(
        "--show-access-token", action="store_true", help="Show OIDC access token."
    )
    parser.add_argument("--show-tgc", action="store_true", help="Show the CAS TGC.")
    parser.add_argument(
        "-s",
        "--scope",
        action="append",
        help="Scope to request. May be specified multiple times.",
    )
    parser.add_argument(
        "--log-level",
        action="store",
        default="WARN",
        choices=["ERROR", "WARN", "INFO", "DEBUG"],
        help="Set logging level.",
    )
    args = parser.parse_args()
    main(args)
