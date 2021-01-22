import time
import webbrowser

import creds
import gs_oauth_tools

TYPE = 'EWS'

MY_ID = '9999'

authManager = gs_oauth_tools.AuthManager(
    microsoftClientID=creds.clientID,
    microsoftTenantID=creds.tenantID,
    debug=True,
)

user = authManager.GetUserByID(MY_ID)
print('19 user=', user)
if user is None:
    print('No user exists for ID="{}"'.format(MY_ID))

    d = authManager.CreateNewUser(MY_ID, authType=TYPE)
    webbrowser.open(d.get('verification_uri'))
    print('User Code=', d.get('user_code'))

while authManager.GetUserByID(MY_ID) is None:
    time.sleep(1)

user = authManager.GetUserByID(MY_ID)
print('31 user=', user)