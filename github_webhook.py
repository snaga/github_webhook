#!/usr/bin/env python

# github_webhook.py
#
# Copyright(c) 2016 Uptime Technologies LLC

from bottle import route, run, request, abort
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

@route('/foobar', method='POST')
def githubwebhook():
    # host check
    is_allowed = False
    for host in allowed_hosts:
        ip = IP(host)
        if request.environ.get('REMOTE_ADDR') in ip:
            is_allowed = True
            
    if is_allowed is False:
        abort(403, "permission denied. [1]")
        return
    
    # sha1 check
    if 'X-Hub-Signature' not in request.headers:
        abort(403, "permission denied. [2]")
        return

    signature = request.headers.get('X-Hub-Signature')
    (algo,digest) = signature.split('=')
    if algo != 'sha1':
        abort(501, "internal error.")
        return

    payload = request['wsgi.input'].read(int(request.headers.get('Content-Length')))
    digest2 = hmac.new(webhook_secret, payload, hashlib.sha1).hexdigest()

    if digest != digest2:
        abort(403, "permission denied. [3]")
        return

    # ok. let's process the request.
    p = subprocess.Popen(urls[request.environ.get('PATH_INFO')],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdoutdata, stderrdata) = p.communicate(None)
    
    resp = {}
    resp['stdout'] = str(stdoutdata)
    resp['stderr'] = str(stderrdata)
    resp['returncode'] = str(p.returncode)

    return json.dumps(resp)

run(host='', port=port, debug=True)
