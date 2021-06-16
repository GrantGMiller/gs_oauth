import time
import webbrowser

import creds
import gs_oauth_tools

import os
os.remove('OAuth.json')
MY_ID = '3888'

authManager = gs_oauth_tools.AuthManager(
    googleJSONpath='google_test_creds.json',
    debug=True,
)

user = authManager.GetUserByID(MY_ID)
print('19 user=', user)
if user is None:
    def NewUserCallback(user):
        print('NewUserCallback(', user)


    print('No user exists for ID="{}"'.format(MY_ID))

    d = authManager.CreateNewUser(
        ID=MY_ID,
        authType='Google',
        initAccessToken='ya29.a0AfH6SMDEGaZOwoBobogbUvI8whBDfQjViI_7tNF4ltttrOniRMTg_Z2arG_rc60J7XtbgDwnRsDkWLsVP72B_b-Df5cFo5kiCX76GB5CDXVj3kGqMJY5aG-dHA1g3Bg3BGkOyEimeobCZbRuNw7AOb7zvwAI',
        initRefreshToken='1//0dX3XvMeTsPugCgYIARAAGA0SNwF-L9IrGB0HdTrDGwbwl14MsZFg4bBGJLpvf3BX9FgQWHsD5E13_HdBzgfufc3_oSEwHattDMc',
        callback=NewUserCallback,
    )
    if d.get('verification_uri'):
        webbrowser.open(d.get('verification_uri'))
        print('User Code=', d.get('user_code'))

while authManager.GetUserByID(MY_ID) is None:
    time.sleep(1)

user = authManager.GetUserByID(MY_ID)
print('31 user=', user)
