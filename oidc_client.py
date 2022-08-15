#! /usr/bin/env python

import argparse
import getpass
import json
import pprint
import re
import sys
from urllib.parse import urlparse

# from oic.utils.http_util import Redirect
import requests
from bs4 import BeautifulSoup
from oic import rndstr
from oic.oic import Client
from oic.oic.message import (AccessTokenResponse, AuthorizationResponse,
                             RegistrationResponse)
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

# https://cas.stage.lafayette.edu/cas/oidc/.well-known

execution_pat = re.compile(r'<input type="hidden" name="execution" value="([^"]+)"')
eventid_pat = re.compile(r'<input type="hidden" name="_eventId" value="([^"]+)"')


def print_headers(r):
    print("- Response Headers -", file=sys.stdout)
    for k, v in r.headers.items():
        print("  {}: {}".format(k, v), file=sys.stdout)
    print("status code:", r.status_code)
    print("")


def main(args):
    verify = not args.no_verify
    user = args.user
    client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
    info = json.load(args.client_info)
    client_reg = RegistrationResponse(**info)
    client.store_registration_info(client_reg)
    client.provider_config(args.issuer)
    client.keyjar[info["client_id"]] = client.keyjar[args.issuer]
    session = {}
    session["state"] = rndstr()
    session["nonce"] = rndstr()
    client_args = {
        "client_id": client.client_id,
        "response_type": "code",
        "scope": ["openid", "email", "profile"],
        "nonce": session["nonce"],
        "redirect_uri": client.registration_response["redirect_uris"][0],
        "state": session["state"],
    }
    auth_req = client.construct_AuthorizationRequest(request_args=client_args)
    login_url = auth_req.request(client.authorization_endpoint)
    print("Login url:", login_url)
    print("")
    if args.passwd_file is not None:
        passwd = args.passwd_file.read().rstrip()
    else:
        passwd = getpass.getpass()
    with requests.Session() as s:
        response = s.get(login_url, verify=verify)
        if args.show_headers:
            print_headers(response)
        content = response.text
        cas_login_url = response.url
        print("CAS Login url:", cas_login_url)
        print("")
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
        response = s.post(cas_login_url, data=data, verify=verify)
        if args.show_headers:
            print_headers(response)
        if "TGC" not in s.cookies.keys():
            print("ERROR: Could not get TGC!", file=sys.stderr)
            sys.exit(1)
        tgc = s.cookies["TGC"]
        if args.show_tgc:
            print("TGC:", tgc)
            print("")
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
        if args.show_headers:
            print_headers(response)
        client_url_with_auth_code = response.headers["Location"]
        print("Client URL with authorization code:", client_url_with_auth_code)
        print("")
    p = urlparse(client_url_with_auth_code)
    query_string = p.query
    aresp = client.parse_response(
        AuthorizationResponse, info=query_string, sformat="urlencoded"
    )
    code = aresp["code"]
    assert aresp["state"] == session["state"]
    client_args = {"code": code}
    resp = client.do_access_token_request(
        state=aresp["state"],
        request_args=client_args,
        authn_method="client_secret_basic",
    )
    if type(resp) != AccessTokenResponse:
        print("No access token!")
        sys.exit(1)
    access_token = aresp["state"]
    if args.show_access_token:
        print("Access token:", access_token)
        print("")
    userinfo = client.do_user_info_request(state=access_token)
    pprint.pprint(dict(userinfo))


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
        "--show-headers", action="store_true", help="Show HTTP headers."
    )
    parser.add_argument(
        "--show-access-token", action="store_true", help="Show OIDC access token."
    )
    parser.add_argument(
        "--show-tgc", action="store_true", help="Show the CAS TGC."
    )
    args = parser.parse_args()
    main(args)
