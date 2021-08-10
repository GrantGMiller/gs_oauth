gs_oauth
========

A Global Scripter module to complete OAuth flow's from Microsoft 365 and Google.

Requirements
============

gs_requests - https://github.com/GrantGMiller/gs_requests

gs_persistent_variables - https://github.com/GrantGMiller/gs_persistent_variables


Example Microsoft Office 365
============================

::

    import creds

    MY_ID = '3888' # An arbitrary identifier for these Oauth credentials
    TYPE = 'Microsoft'

    authManager = AuthManager(
        microsoftClientID=creds.clientID, # The Client ID of your Azure Oauth App
        microsoftTenantID=creds.tenantID, # The Tenant ID of your Azure Oauth App
    )

    user = authManager.GetUserByID(MY_ID)
    print('user=', user)
    if user is None:
        print('No user exists for ID="{}"'.format(MY_ID))

        d = authManager.CreateNewUser(MY_ID, authType=TYPE)
        print('Go to this site:', d.get('verification_uri'))
        print('Enter this User Code:', d.get('user_code'))

    while True:
        user = authManager.GetUserByID(MY_ID)
        if user is None:
            print('Waiting for the user to complete the Oauth flow')
            time.sleep(1)
        else:
            print('Success')
            break

    print('user=', user)

You can find the *microsoftClientID* and *microsoftTenantID* in your App Registrations on https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps

This URL can be helpful to easily fetch your organizations OPENID config: https://login.microsoftonline.com/extron.onmicrosoft.com/.well-known/openid-configuration

Example Google
==============

::

    MY_ID = '3888' # An arbitrary identifier for these Oauth credentials
    TYPE = 'Google'

    authManager = AuthManager(
        googleJSONpath=JSON_PATH, # The .json file for the Oauth App must be placed in the SFTP space on the processor
    )

    user = authManager.GetUserByID(MY_ID)
    print('user=', user)
    if user is None:
        print('No user exists for ID="{}"'.format(MY_ID))

        d = authManager.CreateNewUser(MY_ID, authType=TYPE)
        print('Go to this site:', d.get('verification_uri'))
        print('Enter this User Code:', d.get('user_code'))

    while True:
        user = authManager.GetUserByID(MY_ID)
        if user is None:
            print('Waiting for the user to complete the Oauth flow')
            time.sleep(1)
        else:
            print('Success')
            break

    print('user=', user)
