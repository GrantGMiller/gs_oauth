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
from urllib.parse import urlencode
import requests
import creds
import pyexchange

app = GetApp('Oauth Testing')

CLIENT_ID = creds.clientID
CLIENT_SECRET = creds.clientSecret
AUTH_TOKEN_EXPIRATION_SECONDS = 60 * 60 * 24 * 365

O_AUTH_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/'


def GetRandomString(length=256):
    characters = string.ascii_letters + string.digits
    ret = ''
    for i in range(length):
        ret += random.choice(characters)
    return ret


@app.route('/')
def Index():
    data = {
        'client_id': CLIENT_ID,
        'scope': ' '.join([
            'openid',
            'offline_access',
            'https://outlook.office.com/Calendars.ReadWrite',
            'https://outlook.office.com/EWS.AccessAsUser.All',
        ]),
    }

    url = 'https://login.microsoftonline.com/30f18c78-f7ab-4851-9759-88950e65dc4b/oauth2/v2.0/devicecode'
    print('url=', url)

    resp = requests.post(url, data=data)

    print('56 resp.json()=', resp.json())

    qrURL = 'https://login.microsoftonline.com/common/oauth2/deviceauth?otc={}'.format(
        resp.json().get('user_code', None)
    )
    print('qrURL=', qrURL)

    retResponse = make_response('''
        Please go to <a href="{}">here </a> to authenticate.
        <br>
        Enter this code: <b>{}</b>
        <br>
        <br>
        {}
        <br><br>
        <a href="/check_token">Click here after you have logged in to microsoft.</a>
        
    '''.format(
        resp.json().get('verification_uri', None),
        resp.json().get('user_code', None),
        resp.json().get('message', None),
    ))

    session['device_code'] = resp.json().get('device_code', None)

    return retResponse


@app.route('/check_token')
def CheckToken():
    devCode = session.get('device_code', None)
    print('86 devCode=', devCode)
    resp = requests.post(
        'https://login.microsoftonline.com/{}/oauth2/v2.0/token'.format(creds.tenantID),
        data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'client_id': creds.clientID,
            'device_code': devCode
        }
    )
    print('95 resp.json()=', resp.json())
    session['device_code'] = None
    session['access_token'] = resp.json().get('access_token')
    return redirect('/calendar')



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

    access_token = request.cookies.get('access_token', None) if 'access_token' in request.cookies else session.get('access_token')
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
