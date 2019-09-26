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
    redirect
)
import random
import string
import requests
import creds
import pyexchange

DEBUG = True
CLIENT_ID = creds.clientID
CLIENT_SECRET = creds.clientSecret
AUTH_TOKEN_EXPIRATION_SECONDS = 60 * 60 * 24 * 365

app = GetApp('Oauth Testing')


def GetRandomString(length=256):
    characters = string.ascii_letters + string.digits
    ret = ''
    for i in range(length):
        ret += random.choice(characters)
    return ret


@app.route('/')
def Index():
    return redirect('/login')


@app.route('/login')
def Login():
    return '''
        <form action='/submit_login' method='POST'>
        Username: <input name="username" value={}>
        <br>
        Password: <input name='password' type='password' value={}>
        <br>
        <input type='submit'>
        </form>
    '''.format(creds.username if DEBUG else '', creds.password if DEBUG else '')


@app.route('/submit_login', methods=['POST'])
def SubmitLogin():
    username = request.form.get('username', None)
    password = request.form.get('password', None)
    if username and password:
        print('104 _session=', json.dumps(dict(session), indent=2, sort_keys=True))
        data = {
            "grant_type": "password",
            "client_id": CLIENT_ID,
            'scope': ' '.join([
                'openid',
                'offline_access',
                'https://outlook.office.com/Calendars.ReadWrite',
                'https://outlook.office.com/EWS.AccessAsUser.All',
            ]),
            # "redirect_uri": "http://localhost:5000/auth_callback",
            # "client_secret": CLIENT_SECRET,  # dont send this
            'username': creds.username if DEBUG else username,
            'password': creds.password if DEBUG else password,
        }
        print('105 data=', data)
        url = 'https://login.microsoftonline.com/30f18c78-f7ab-4851-9759-88950e65dc4b/oauth2/v2.0/token'
        resp = requests.post(url, data=data)

        print('113 resp.json()=', resp.json())
        if 'error' in resp.json():
            err = resp.json().get('error_description')
            returnResp = make_response('{}<br><a href="/">Home</a>'.format(err))
            return returnResp

        expireDT = datetime.datetime.now() + datetime.timedelta(seconds=AUTH_TOKEN_EXPIRATION_SECONDS)
        returnResp = redirect('/calendar')
        for key in ['access_token', 'id_token', 'refresh_token']:
            val = resp.json().get(key, None)
            print('128 key=', key, ', val=', val)
            if val:
                returnResp.set_cookie(
                    key, val,
                    expires=expireDT,
                )
                # _session[s] = resp.json().get(s)

        return returnResp
    else:
        print('username=', username, 'password=', password)
        return redirect('/login')




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
    print('137 _session=', json.dumps(dict(session), indent=2, sort_keys=True))
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
