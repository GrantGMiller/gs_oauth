import requests
import time

CLIENT_ID = '459ac21c-adde-45a5-abf3-85d757ba2fdf'
TENANT_ID = '30f18c78-f7ab-4851-9759-88950e65dc4b'

# Get the "user code", that the user will enter into https://microsoft.com/devicelogin
data = {
    'client_id': CLIENT_ID,
    'scope': ' '.join([
        'openid',
        'offline_access',
        'https://outlook.office.com/Calendars.ReadWrite',
        'https://outlook.office.com/EWS.AccessAsUser.All',
    ]),
}
url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/devicecode'.format(TENANT_ID)
resp = requests.post(url, data=data)

verificationURL = resp.json().get('verification_uri')
userCode = resp.json().get('user_code')
deviceCode = resp.json().get('device_code')
interval = resp.json().get('interval')
expiresIn = resp.json().get('expires_in')

startTime = time.monotonic()

print('Please navigate to {} and enter the code "{}"'.format(verificationURL, userCode))

# This code must now check the device code once per "interval"
url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/token'.format(TENANT_ID)
data = {
    'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
    'client_id': CLIENT_ID,
    'device_code': deviceCode
}
while time.monotonic() - startTime < expiresIn:
    resp = requests.post(url, data)
    print('resp=', resp.json())
    accessToken = resp.json().get('access_token', None)
    if accessToken:
        refreshToken = resp.json().get('refresh_token', None)
        expiresAt = resp.json().get('expires_in') + time.monotonic()
    if accessToken is None:
        # The user has not authenticated yet, check again in "interval" seconds
        time.sleep(interval)
    else:
        # The user authenticated.
        print('You can now connect to Office 365 using the accessToken "{}"'.format(accessToken))
        break
else:
    print('The Device Code expired. Please start over')

while True:
    # You must periodically "refesh" the accessToken using the refreshToken
    while time.monotonic() < expiresAt:
        print('The accessToken is still valid')
        print('It will expire in {} seconds'.format(int(expiresAt - time.monotonic())))
        time.sleep(1)

    # The accessToken has expired, refresh it
    url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/token'.format(TENANT_ID)
    data = {
        'client_id': CLIENT_ID,
        'scope': ' '.join([
            'openid',
            'offline_access',
            'https://outlook.office.com/Calendars.ReadWrite',
            'https://outlook.office.com/EWS.AccessAsUser.All',
        ]),
        'refresh_token': refreshToken,
        'grant_type': 'refresh_token',
    }
    resp = requests.post(url, data)
    accessToken = resp.json().get('access_token', None)
    refreshToken = resp.json().get('refresh_token', None)
    expiresAt = resp.json().get('expires_in') + time.monotonic()

    print('Your new access token is "{}"'.format(accessToken))
