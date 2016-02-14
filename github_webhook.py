#!/usr/bin/env python

# github_webhook.py
#
# Copyright(c) 2016 Uptime Technologies LLC

import BaseHTTPServer
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

class GithubWebhookRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def do_GET(self):
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

        # ok. process request.
        self.send_response(200, "webhook called.")
        self.end_headers()
        p = subprocess.Popen(urls[self.path], stdout=subprocess.PIPE)
        (stdoutdata, stderrdata) = p.communicate(None)

        resp = ""
        for h in self.headers:
            resp = resp + str(h) + ": " + self.headers[h] + "\n"
        resp = resp + "\n"
        resp = resp + str(stdoutdata)
        resp = resp + "\nreturncode: " + str(p.returncode)

        self.wfile.write(resp)
        print(resp)

class GithubWebhook():
    httpd = None

    def __init__(self, server_addr, server_port):
        self.httpd = BaseHTTPServer.HTTPServer((server_addr, server_port), GithubWebhookRequestHandler)

    def run(self):
        while True:
            self.httpd.handle_request()

hookserver = GithubWebhook('', port)

hookserver.run()
