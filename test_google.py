import time
import webbrowser

import creds
import gs_oauth_tools

TYPE = 'Google'

MY_ID = '3888'

authManager = gs_oauth_tools.AuthManager(
    googleJSONpath='google_test_creds.json',
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