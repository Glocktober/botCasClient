#!/usr/bin/env python3
# copyright 2021 r.kras - see LICENSE.txt for details
"""
 A Bottle web app using CAS authentication (casAuth.CasSP)
""" 
import json

from bottle import Bottle, request, response
from BottleSessions import BottleSessions
from botCasSP import CasSP

app = Bottle()

# Session middleware
sessions_config = {
    'session_cookie': 'CASCli',
    'session_expire': 900,
    'session_backing': {
        'cache_type' : 'FileSystem',  # 'Redis'
        'cache_dir' : './.cache'
    }
}
ses = BottleSessions(app, **sessions_config)

# configure CAS Client
cas_client_config = {
    "cas_server_base_url" : "http://localhost:8000/cas",
    "cas_version" : "v2", 
    "cas_attr_list" : ["givenname", "uid", "surname", "groups", "occid"],
}
auth = CasSP(app, cas_client_config, db=ses.backing)

# Dump session information
@app.route('/.sess', authn=False)
def dump_sess():
    response.set_header('content-type','text/plain')
    return json.dumps(request.session, indent=4)

# Login route for app
@app.route(['/logon','/login'])
@auth.require_login
def is_login():
    return request.session['username']

# Logout route for app
@app.route(['/logoff','/logout'])
def is_logoff():
    if auth.is_authenticated:
        auth.initiate_logout(next=request.url)
    return 'ok'

if __name__ == "__main__":
    app.run(port=5000, debug=True, reloader=True)
