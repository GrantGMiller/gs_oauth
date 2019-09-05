import datetime
import json

from pytz import timezone

from flask_tools import (
    GetApp,
)
from flask import (
    request,
    make_response,
    session,
)
import random
import string
from urllib.parse import urlencode
import requests
import creds
import pyexchange

app = GetApp('Oauth Testing')

CLIENT_ID = creds.clientID
CLIENT_SECRET = creds.clientSecret
AUTH_TOKEN_EXPIRATION_SECONDS = 60 * 60 * 24 * 365

# O_AUTH_URL = 'https://login.windows.net/common/oauth2/'
O_AUTH_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/'


def GetRandomString(length=256):
    characters = string.ascii_letters + string.digits
    ret = ''
    for i in range(length):
        ret += random.choice(characters)
    return ret


@app.route('/')
def Index():
    state = GetRandomString(8)
    nonce = GetRandomString(8)

    # data = {
    #     'client_id': CLIENT_ID,
    #     'response_type': 'id_token',
    #     'redirect_uri': 'http://localhost:5000/auth_callback',
    #     'response_mode': 'form_post',
    #     'scope': 'openid',
    #     'state': state,
    #     'nonce': nonce,
    # }
    data = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': 'http://localhost:5000/auth_callback',
        'response_mode': 'query',
        'scope': ' '.join([
            'openid',
            'offline_access',
            'https://outlook.office.com/Calendars.ReadWrite',
            'https://outlook.office.com/EWS.AccessAsUser.All',
            # 'https://outlook.office365.com/EWS/Exchange.asmx',
            # 'https://outlook.office.com',
        ]),
        'state': state,
    }
    session['state'] = state
    session['nonce'] = nonce

    url = '{}authorize?{}'.format(O_AUTH_URL, urlencode(data))
    print('url=', url)

    resp = make_response('''<a href="{}">Login to Microsoft</a>'''.format(url))
    expireDT = datetime.datetime.now() + datetime.timedelta(seconds=AUTH_TOKEN_EXPIRATION_SECONDS)
    resp.set_cookie(
        'state', state,
        expires=expireDT,
    )
    return resp


@app.route('/auth_callback', methods=['GET', 'POST'])
def AuthCallback(*a, **k):
    print('request.form=', request.form)
    print('request.values=', request.values)

    if request.values.get('state') == session.get('state', None):
        session['code'] = request.values.get('code')
        resp = make_response('''code received<br><a href='/get_access_token'>Get Access Token</a>''')
        return resp
    else:
        return 'state does not match <br> <a href="/">Home</a>', 401


# @app.route('/access_token_callback', methods=['GET', 'POST'])
# def AccessTokenCallback(*a, **k):
#     print('AccessTokenCallback(', a, k)
#     return 'AccessTokenCallback'


@app.route('/get_access_token')
def GetAccessToken():
    print('104 session=', json.dumps(dict(session), indent=2, sort_keys=True))
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        'scope': ' '.join([
            'openid',
            'offline_access',
            'https://outlook.office.com/Calendars.ReadWrite',
            'https://outlook.office.com/EWS.AccessAsUser.All',
            # 'https://outlook.office365.com/EWS/Exchange.asmx',
            # 'https://outlook.office.com',
        ]),
        "code": session.get('code', None),
        "redirect_uri": "http://localhost:5000/auth_callback",
        # "client_secret": CLIENT_SECRET # dont send this
    }
    print('105 data=', data)
    url = '{}token'.format(O_AUTH_URL)
    resp = requests.post(url, data=data)
    print('113 resp.json()=', resp.json())
    expireDT = datetime.datetime.now() + datetime.timedelta(seconds=AUTH_TOKEN_EXPIRATION_SECONDS)
    returnResp = make_response('access_token received<br><a href="/calendar">View Calendar</a>')
    for key in ['access_token', 'id_token', 'refresh_token']:
        val = resp.json().get(key, None)
        print('128 key=', key, ', val=', val)
        returnResp.set_cookie(
            key, val,
            expires=expireDT,
        )
        # session[s] = resp.json().get(s)

    return returnResp


@app.route('/calendar')
def Calendar():
    URL = 'https://outlook.office365.com/EWS/Exchange.asmx'

    # Set up the connection to Exchange with basic auth
    # connection = pyexchange.ExchangeBasicAuthConnection(
    #     url=URL,
    #     username=creds.username,
    #     password=creds.password,
    # )
    # Set up the connection to exchange with Oauth token
    print('137 session=', json.dumps(dict(session), indent=2, sort_keys=True))
    print('138 request.values=', json.dumps(dict(request.values), indent=2, sort_keys=True))
    print('151 request.cookies=', json.dumps(dict(request.cookies), indent=2, sort_keys=True))

    access_token = request.cookies.get('access_token', None)
    if access_token is None:
        print('152 ERROR access_token is None')

    connection = pyexchange.ExchangeOauthConnection(
        url=URL,
        access_token=access_token,
    )

    exchange = pyexchange.Exchange2010Service(connection)

    nowDT = datetime.datetime.utcnow()
    startDT = timezone("US/Eastern").localize(nowDT)
    endDT = timezone("US/Eastern").localize(nowDT + datetime.timedelta(days=1))

    print('startDT=', startDT)
    print('endDT=', endDT)

    callist = exchange.calendar(creds.username).list_events(
        start=startDT,
        end=endDT,
        details=True
    )
    s = '<table border="1"><tr><th>Start (UTC)</th><th>End (UTC)</th><th>Subject</th></tr>'
    for event in callist.events:
        s += '<tr>'
        s += "<td>{}</td>".format(event.start)
        s += "<td>{}</td>".format(event.end)
        s += "<td>{}</td>".format(event.subject)
        s += '</tr>'
    print('events=', s)
    return s + '<br><br>'


if __name__ == '__main__':
    app.run(debug=True)
