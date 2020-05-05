#!/usr/bin/env python

from functools import partial
from http.server import (
    BaseHTTPRequestHandler,
    HTTPServer,
)

import base64
import json
import logging
import pprint
import threading
import urllib
from urllib.parse import urlparse
import webbrowser

from requests_oauthlib import oauth2_session


class RedirectHandler(BaseHTTPRequestHandler):
    last_response = None

    def do_GET(self):
        RedirectHandler.last_response = self.path
        content = b"<html><head></head><body>You have been logged in and your token was sent to the terminal.</body></html>"
        self.send_response(200, "OK")
        self.send_header("Content-Length", len(content))
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(content)


class CloseHandler(BaseHTTPRequestHandler):
    last_response = None

    def do_GET(self):
        RedirectHandler.last_response = self.path


def print_payload(type_, token):
    payload = token.split('.')[1]
    payload += '=' * (4 - len(payload) % 4)
    payload = base64.b64decode(payload)
    print("==== {t} payload:".format(t=type_))
    pprint.pprint(json.loads(payload))


def get_redirect(server_name='localhost', port='8123'):
    server_address = (server_name, port)
    httpd = HTTPServer(server_address, RedirectHandler)
    httpd.handle_request()


def login(client_info, oauth_provider, scopes):
    oauth = oauth2_session.OAuth2Session(client_id=client_info['id'],
                                         redirect_uri=client_info['redirect_uri'],
                                         scope=scopes)
    url, state = oauth.authorization_url(oauth_provider['authorization_endpoint'])
    redirect_uri = urlparse(client_info['redirect_uri'])
    f = partial(get_redirect, server_name=redirect_uri.hostname, port=redirect_uri.port)
    t = threading.Thread(target=f)
    t.start()
    webbrowser.open(url)
    t.join()
    query = urllib.parse.urlparse(RedirectHandler.last_response).query
    parts = urllib.parse.parse_qs(query)
    session = oauth2_session.OAuth2Session(client_info['id'], state=state,
                                           redirect_uri=client_info['redirect_uri'])
    token = session.fetch_token(oauth_provider['token_endpoint'],
                                client_secret=client_info['secret'],
                                code=parts['code'][0])
    return token


if __name__ == '__main__':
    import argparse
    argparser = argparse.ArgumentParser()
    argparser.add_argument('-c', '--config', default='private.cfg', help='Configuration file')
    argparser.add_argument('-s', '--scope', action='append', help='scopes to request')
    argparser.add_argument('--verbose', '-v', action='count')
    argparser.add_argument('--access-token', '-a', dest='tokens', action='append_const', const='access_token')
    argparser.add_argument('--id-token', '-i', dest='tokens', action='append_const', const='id_token')
    argparser.add_argument('--refresh-token', '-r', dest='tokens', action='append_const', const='refresh_token')
    argparser.add_argument('--payload', action="store_true", help="print access token payload")
    argparser.add_argument('--env', action="store_true", help="output (ID|ACCESS|REFRESH)_TOKEN='{TOKEN}' for direct evaluation in environment")
    args = argparser.parse_args()
    scopes = set(('openid', 'profile'))
    if args.scope:
        scopes |= set(args.scope)
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    import configparser
    cp = configparser.ConfigParser()
    cp.read(args.config)
    client_info = cp['client']
    oauth_provider = cp['oauth_provider']
    token = login(client_info, oauth_provider, scopes)
    if args.payload:
        printable = {'id_token', 'access_token'}
        to_print = printable.intersection(args.tokens) or printable
        for tok in to_print:
            print_payload(tok, token[tok])
    if args.env:
        for token_type in (args.tokens or ('id_token', 'access_token', 'refresh_token')):
            if token_type in token:
                print(f'{token_type.upper()}={token[token_type]}\n')
    elif not args.tokens:
        print("")
        pprint.pprint(token)
        print("")
    else:
        print("")
        for token_type in args.tokens:
            print(f'{token_type: <15} {token[token_type]}\n')
