#!/usr/bin/env python

# github_webhook.py
#
# Copyright(c) 2016 Uptime Technologies LLC

import BaseHTTPServer
import hashlib
import hmac
import json
import subprocess
# pip install IPy
from IPy import IP

port = 8888

urls = {
    '/foobar': ['ls','-l','/']
}

allowed_hosts = [
    # What IP addresses does GitHub use that I should whitelist? - User Documentation
    # https://help.github.com/articles/what-ip-addresses-does-github-use-that-i-should-whitelist/
    '192.30.252.0/22',
    # local test
    '10.0.2.0/24'
]

webhook_secret = 'your_secret_here'

class GithubWebhookRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def do_POST(self):
        # host check
        is_allowed = False
        for host in allowed_hosts:
            ip = IP(host)
            if self.client_address[0] in ip:
                is_allowed = True

        if is_allowed is False:
            self.send_response(403, "permission denied.")
            self.end_headers()
            self.wfile.write("permission denied.")
            return

        # url check
        if self.path not in urls:
            self.send_response(404, "url not found.")
            self.end_headers()
            self.wfile.write("url not found.")
            return

        # sha1 check
        if 'X-Hub-Signature' not in self.headers:
            self.send_response(403, "permission denied.")
            self.end_headers()
            self.wfile.write("permission denied.")
            return

        signature = self.headers['X-Hub-Signature']
        (algo,digest) = signature.split('=')
        if algo != 'sha1':
            self.send_response(501, "internal error.")
            self.end_headers()
            self.wfile.write("internal error.")
            return

        payload = self.rfile.read(int(self.headers.getheader('content-length')))
        digest2 = hmac.new(webhook_secret, payload, hashlib.sha1).hexdigest()

        if digest != digest2:
            self.send_response(403, "permission denied.")
            self.end_headers()
            self.wfile.write("permission denied.")
            return

        # ok. let's process the request.
        p = subprocess.Popen(urls[self.path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdoutdata, stderrdata) = p.communicate(None)

        self.send_response(200, "webhook invoked.")
        self.end_headers()
        resp = {}
        resp['stdout'] = str(stdoutdata)
        resp['stderr'] = str(stderrdata)
        resp['returncode'] = str(p.returncode)

        self.wfile.write(json.dumps(resp))

#        print(json.dumps(resp))

class GithubWebhook():
    httpd = None

    def __init__(self, server_addr, server_port):
        self.httpd = BaseHTTPServer.HTTPServer((server_addr, server_port), GithubWebhookRequestHandler)

    def run(self):
        while True:
            self.httpd.handle_request()

hookserver = GithubWebhook('', port)

hookserver.run()
