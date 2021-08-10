import datetime
import json
import time

try:
    import requests
except:
    import gs_requests as requests

from urllib.parse import urlencode

# based on the steps here:https://developers.google.com/identity/protocols/OAuth2ForDevices
from persistent_variables import PersistentVariables as PV

try:
    import aes_tools
except Exception as e:
    if 'aes_tools' in e.args:
        print('no aes_tools module found. Credentials will be stored in plain text')
    else:
        print(e)
try:
    from extronlib_pro import File, Wait, ProgramLog
except:
    from extronlib.system import File, Wait, ProgramLog

# USE_COMMON_TENANT = False  # per microsoft: Usage of the /common endpoint is not supported for such applications created after '10/15/2018'

GOOGLE_SCOPES = [
    'https://www.googleapis.com/auth/calendar',
    'https://www.googleapis.com/auth/drive.file',
]

MICROSOFT_SCOPES = [
    'openid',
    'offline_access',
    'https://outlook.office.com/Calendars.ReadWrite',
    # 'https://outlook.office.com/EWS.AccessAsUser.All',
    'email',
    'User.Read'
]


def SetMicrosoftScopes(scopeList):
    global MICROSOFT_SCOPES
    MICROSOFT_SCOPES = scopeList


class _BaseOauthDeviceCode:
    def print(self, *a, **k):
        if self._debug:
            print(*a, **k)


class OauthDeviceCode_Google(_BaseOauthDeviceCode):
    # https://console.developers.google.com/apis/dashboard

    def __init__(self, jsonPath, initAccessToken=None, initRefreshToken=None,
                 initAccessTokenExpiresAt=None, debug=False, **kwargs):
        # pass kwargs like
        # google_client_id='',
        # google_client_secret='',
        # google_auth_uri='',
        # google_redirect_uris='',

        self._debug = debug

        self.print('kwargs=', kwargs)

        if jsonPath:
            with File(jsonPath, mode='rt') as file:
                self._creds = json.loads(file.read())
        else:
            self._creds = {'installed': {}}
            for key, value in kwargs.items():
                if key.startswith('google'):
                    key = key.replace('google_', '')
                    self._creds['installed'][key] = value

        self.print('self._creds=', self._creds)
        self._session = requests.session()

        self.type = 'Google'

        # will be filled in later
        self._accessToken = initAccessToken
        self._refreshToken = initRefreshToken
        self._accessTokenExpiresAt = initAccessTokenExpiresAt or time.time()  # time.time
        self._verificationURI = None
        self._userCode = None
        self._deviceCode = None
        self._deviceCodeExpiresAt = time.time()
        self._interval = 5
        self._lastRequest = time.time() - self._interval
        self.message = None

    def print(self, *a, **k):
        if self._debug:
            print(*a, **k)

    def _InitVerificationURI(self):
        authURL = '{}?{}'.format(
            self._creds['installed']['auth_uri'],
            urlencode({
                'client_id': self._creds['installed']['client_id'],
                'redirect_uri': self._creds['installed']['redirect_uris'][-1],
                'scope': ' '.join(GOOGLE_SCOPES),
                'access_type': 'offline',
                'response_type': 'code',
            })
        )
        self._verificationURI = authURL
        return authURL

    def _DoRequest(self, method, url, data=None, params=None):
        self.print('_DoRequests(', method, url, data, params)
        resp = self._session.request(method=method, url=url, data=data, params=params)

        self.print('resp.text=', resp.text)
        self.print('resp.status_code=', resp.status_code)
        self.print('resp.reason=', resp.reason)

        return resp

    def GetUserCode(self):
        data = {
            'client_id': self._creds['installed']['client_id'],
            'scope': ' '.join(GOOGLE_SCOPES),
        }
        url = 'https://accounts.google.com/o/oauth2/device/code'
        resp = requests.post(url, data=data)
        self.print('105 resp=', resp.json(), resp.reason)

        if not resp.ok:
            self.print('url=', url)
            self.print('data=', data)
            print('resp.text=', resp.text)
            raise PermissionError(resp.text)
            return

        self._verificationURI = resp.json().get('verification_url')
        self._userCode = resp.json().get('user_code')
        self._deviceCode = resp.json().get('device_code')
        self._interval = resp.json().get('interval', self._interval)
        self._deviceCodeExpiresAt = time.time() + resp.json().get('expires_in')
        self._lastRequest = time.time()
        self.print('')
        return self._userCode

    @property
    def VerificationURI(self):
        return self._verificationURI

    @property
    def Interval(self):
        return self._interval

    def DeviceCodeExpired(self):
        self.print('time until code expires', self._deviceCodeExpiresAt - time.time())
        return time.time() > self._deviceCodeExpiresAt

    def GetRefreshToken(self):
        return self._refreshToken

    def GetAccessTokenExpriesAt(self):
        return self._accessTokenExpiresAt

    def GetAccessToken(self):
        """
        Tries to get an access token.
        Call this before every HTTP request that needs oauth,
            because the token may have expired.
        This method will refresh the token if needed and return the new token.
        Might return None if the user has not authenticated yet
        :return: str or None
        """
        self.print('GetAccessToken()')
        if time.time() - self._lastRequest < self._interval:
            # only make request once per "interval"
            return self._accessToken

        if self._accessToken:
            # we already received an access token previously
            if time.time() > self._accessTokenExpiresAt:
                self.print('The accessToken is expired, use the refreshToken to get a new one')
                url = 'https://oauth2.googleapis.com/token'
                self.print('self._creds=', self._creds)
                data = {
                    'client_id': self._creds['installed']['client_id'],
                    'client_secret': self._creds['installed']['client_secret'],
                    'refresh_token': self._refreshToken,
                    'grant_type': 'refresh_token',
                }
                try:
                    resp = requests.post(url, data)
                    self._lastRequest = time.time()
                    self.print('Refresh Token request complete')
                    self.print('resp.json()=', resp.json())
                    self._accessToken = resp.json().get('access_token')
                    self._refreshToken = resp.json().get('refresh_token',
                                                         self._refreshToken)  # google uses the same refresh token?
                    self._accessTokenExpiresAt = time.time() + resp.json().get('expires_in')
                except Exception as e:
                    ProgramLog(str(e), 'error')
                return self._accessToken
            else:
                delta = int(self._accessTokenExpiresAt - time.time())
                self.print('The access token will expire in {}'.format(
                    datetime.timedelta(seconds=delta)))
                self.print('The access token is still good, return it.')
                return self._accessToken
        else:
            # This is the first time we are retrieving an access token
            url = 'https://oauth2.googleapis.com/token'
            resp = requests.post(
                url,
                data={
                    'grant_type': 'http://oauth.net/grant_type/device/1.0',
                    'client_id': self._creds['installed']['client_id'],
                    'client_secret': self._creds['installed']['client_secret'],
                    'code': self._deviceCode
                }
            )
            self._lastRequest = time.time()
            self.print('192 resp=', resp.json())
            self._accessToken = resp.json().get('access_token', None)
            self._refreshToken = resp.json().get('refresh_token', None)
            if self._accessToken:
                self._accessTokenExpiresAt = time.time() + resp.json().get('expires_in', None)
            return self._accessToken


class OauthDeviceCode_Microsoft(_BaseOauthDeviceCode):
    def __init__(
            self,
            clientID,
            tenantID,
            initAccessToken=None,
            initRefreshToken=None,
            initAccessTokenExpiresAt=None,
            gcc=False,
            debug=False
    ):
        self._clientID = clientID
        self._tenantID = tenantID

        self.type = 'Microsoft'
        self._debug = debug
        self._gcc = gcc

        # will be filled in later
        self._accessToken = initAccessToken
        self._refreshToken = initRefreshToken
        self._accessTokenExpiresAt = initAccessTokenExpiresAt or time.time()  # time.time
        self._verificationURI = None
        self._userCode = None
        self._deviceCode = None
        self._deviceCodeExpiresAt = time.time()
        self._interval = 5
        self._lastRequest = time.time() - self._interval
        self.message = None

    def print(self, *a, **k):
        if self._debug:
            print(*a, **k)

    def GetUserCode(self):
        data = {
            'client_id': self._clientID,
            'scope': ' '.join(MICROSOFT_SCOPES),
        }
        if self._gcc:
            url = 'https://login.microsoftonline.us/{}/oauth2/v2.0/devicecode'.format(self._tenantID)
        else:
            url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/devicecode'.format(self._tenantID)
        resp = requests.post(url, data=data)
        print('245 resp=', resp.json())
        if not resp.ok:
            print('url=', url)
            print('249 data=', data)
            print('resp.reason=', resp.reason)
            return

        self._verificationURI = resp.json().get('verification_uri')
        self._userCode = resp.json().get('user_code')
        self._deviceCode = resp.json().get('device_code')
        self._interval = resp.json().get('interval')
        self._deviceCodeExpiresAt = time.time() + resp.json().get('expires_in', 0)
        self._lastRequest = time.time()
        self.message = resp.json().get('message', None)

        return self._userCode

    @property
    def VerificationURI(self):
        return self._verificationURI

    @property
    def Interval(self):
        return self._interval

    def DeviceCodeExpired(self):
        return time.time() > self._deviceCodeExpiresAt

    def GetRefreshToken(self):
        return self._refreshToken

    def GetAccessTokenExpriesAt(self):
        return self._accessTokenExpiresAt

    def GetAccessToken(self):
        """
        Tries to get an access token.
        Call this before every HTTP request that needs oauth,
            because the token may have expired.
        This method will refresh the token if needed and return the new token.
        Might return None if the user has not authenticated yet
        :return: str or None
        """
        self.print('GetAccessToken()')
        if time.time() - self._lastRequest < self._interval:
            # only make request once per "interval"
            return self._accessToken

        if self._accessToken:
            # we already received an access token previously
            if time.time() > self._accessTokenExpiresAt:
                self.print('The accessToken is expired, use the refreshToken to get a new one')

                if self._gcc:
                    url = 'https://login.microsoftonline.us/{}/oauth2/v2.0/token'.format(self._tenantID)
                else:
                    url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/token'.format(self._tenantID)

                data = {
                    'client_id': self._clientID,
                    'scope': ' '.join(MICROSOFT_SCOPES),
                    'refresh_token': self._refreshToken,
                    'grant_type': 'refresh_token',
                }
                try:
                    resp = requests.post(url, data)
                    self._lastRequest = time.time()
                    self.print('Refresh Token request complete')
                    self.print('resp.json()=', resp.json())
                    self._accessToken = resp.json().get('access_token')
                    self._refreshToken = resp.json().get('refresh_token')
                    self._accessTokenExpiresAt = time.time() + resp.json().get('expires_in')
                except Exception as e:
                    ProgramLog(str(e), 'error')
                return self._accessToken
            else:
                delta = int(self._accessTokenExpiresAt - time.time())
                self.print('The access token will expire in {}'.format(
                    datetime.timedelta(seconds=delta)))
                self.print('The access token is still good, return it.')
                return self._accessToken
        else:
            # This is the first time we are retrieving an access token

            if self._gcc:
                url = 'https://login.microsoftonline.us/{}/oauth2/v2.0/token'.format(self._tenantID)
            else:
                url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/token'.format(self._tenantID)

            resp = requests.post(
                url,
                data={
                    'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                    'client_id': self._clientID,
                    'device_code': self._deviceCode
                }
            )
            self._lastRequest = time.time()
            print('resp=', resp.json())
            self._accessToken = resp.json().get('access_token', None)
            self._refreshToken = resp.json().get('refresh_token', None)
            if self._accessToken:
                self._accessTokenExpiresAt = time.time() + resp.json().get('expires_in', None)
            return self._accessToken


class User:
    def __init__(self, ID, authManagerParent, authType, debug=False, gcc=False):
        self._debug = debug
        self._ID = ID
        self.gcc = gcc

        data = authManagerParent.Get(self)
        if authType == 'Google':
            self._oa = OauthDeviceCode_Google(
                jsonPath=authManagerParent.GoogleJSONPath,
                initAccessToken=data.get('accessToken', None),
                initRefreshToken=data.get('refreshToken', None),
                initAccessTokenExpiresAt=data.get('expiresAt', None),
                debug=self._debug,
            )
        elif authType == 'Microsoft':
            self._oa = OauthDeviceCode_Microsoft(
                clientID=authManagerParent.ClientID,
                tenantID=authManagerParent.TenantID,
                initAccessToken=data.get('accessToken', None),
                initRefreshToken=data.get('refreshToken', None),
                initAccessTokenExpiresAt=data.get('expiresAt', None),
                debug=self._debug,
                gcc=self.gcc,
            )
        self._emailAddress = data.get('emailAddress', None)
        self._authManagerParent = authManagerParent

    def print(self, *a, **k):
        if self._debug:
            print(*a, **k)

    def __str__(self):
        return '<User: Type={}, ID={}, EmailAddress={}, AccessToken={}>'.format(self.type, self.ID, self.EmailAddress,
                                                                                self.GetAccessToken()[
                                                                                :10] + '...' if self.GetAccessToken() else None)

    @property
    def ID(self):
        return self._ID

    @property
    def Data(self):
        return {
            'accessToken': self._oa.GetAccessToken(),
            'refreshToken': self._oa.GetRefreshToken(),
            'expiresAt': self._oa.GetAccessTokenExpriesAt(),
            'emailAddress': self._emailAddress,
            'type': self._oa.type,
            'gcc': False if 'Microsoft' not in self._oa.type else self.gcc,
        }

    @property
    def AccessToken(self):
        ret = self._oa.GetAccessToken()
        self._authManagerParent.Update(self)
        return ret

    @property
    def RefreshToken(self):
        ret = self._oa.GetRefreshToken()
        self._authManagerParent.Update(self)
        return ret

    @property
    def EmailAddress(self):
        if self._oa.type != 'Microsoft':
            return

        if self._emailAddress is None:
            resp = requests.get(
                # 'https://graph.microsoft.com/v1.0/me', #invalid audience
                'https://outlook.office.us/api/v2.0/me' if self.gcc else 'https://outlook.office.com/api/v2.0/me',
                headers={
                    'Authorization': 'Bearer {}'.format(self._oa.GetAccessToken()),
                    'Content-Type': 'application/json',
                }
            )
            self.print('resp.json()=', resp.json())
            self.print('resp.status_code=', resp.status_code)
            if resp.status_code == 200:
                self._emailAddress = resp.json().get('EmailAddress', None)
                self._authManagerParent.Update(self)

        return self._emailAddress

    def GetAccessToken(self):
        return self.AccessToken

    @property
    def type(self):
        return self._oa.type


class AuthManager:
    def __init__(
            self,
            microsoftClientID=None,
            microsoftTenantID=None,
            microsoftGCCHigh=False,
            googleJSONpath=None,
            debug=False,
            fileClass=File,

            **kwargs
    ):
        self._microsoftClientID = microsoftClientID
        self._microsoftTenantID = microsoftTenantID
        self._microsoftGCCHigh = microsoftGCCHigh
        self._googleJSONpath = googleJSONpath
        self._debug = debug

        self.googleKwargs = {}
        for key, value in kwargs.items():
            if key.startswith('google'):
                self.googleKwargs[key] = value

        self._pv = PV(
            'OAuth.json',
            fileMode='t' if fileClass == File else 'b',
        )
        '''
        Data stored like this:
        {
        str(uniqueID): {
            'type': str #like 'Google' or 'Microsoft'
            'accessToken': str(),
            'refreshToken': str(),
            'expiresAt': float() # time.time()
            'emailAddress': str(email)
            }
        }
        '''

    def print(self, *a, **k):
        if self._debug:
            print(*a, **k)

    @property
    def ClientID(self):
        return self._microsoftClientID

    @property
    def TenantID(self):
        return self._microsoftTenantID

    @property
    def GoogleJSONPath(self):
        return self._googleJSONpath

    @property
    def GoogleData(self):
        with open(self._googleJSONpath, mode='rt') as file:
            d = json.loads(file.read())['installed']
        return d

    def Update(self, userObj):
        self._pv.Set(userObj.ID, userObj.Data)

    def Get(self, userObj):
        return self._pv.Get(userObj.ID, {})

    def GetUserByID(self, ID: object) -> object:
        assert isinstance(ID, str), '"ID" must be a string not {}'.format(type(ID))

        d = self._pv.Get()
        if ID in d:
            return User(
                ID,
                authManagerParent=self,
                authType=d[ID]['type'],
                debug=self._debug,
                gcc=self._microsoftGCCHigh,
            )
        else:
            return None  # no user exist, you can use CreateNewUser if you like

    def CreateNewUser(
            self,
            ID,
            authType='Microsoft',
            callback=None,
            initAccessToken=None,
            initRefreshToken=None,
    ):
        self.print('CreateNewUser(', ID, authType, callback, initAccessToken, initRefreshToken)
        assert isinstance(ID, str), '"ID" must be a string not {}'.format(type(ID))

        if authType == 'Google':
            tempOA = OauthDeviceCode_Google(
                self._googleJSONpath,
                debug=self._debug,
                initAccessToken=initAccessToken,
                initRefreshToken=initRefreshToken,
                initAccessTokenExpiresAt=time.time() if initAccessToken else None,  # assume its expired

                **self.googleKwargs,
            )
        elif authType == 'Microsoft':
            tempOA = OauthDeviceCode_Microsoft(
                self._microsoftClientID,
                self._microsoftTenantID,
                debug=self._debug,
                initAccessToken=initAccessToken,
                initRefreshToken=initRefreshToken,
                initAccessTokenExpiresAt=time.time() if initAccessToken else None,  # assume its expired
                gcc=self._microsoftGCCHigh,
            )
        else:
            raise TypeError('Unrecognized authType "{}"'.format(authType))

        if initAccessToken and tempOA.GetAccessToken():
            self._pv.Set(ID, {
                'accessToken': tempOA.GetAccessToken(),
                'refreshToken': tempOA.GetRefreshToken(),
                'expiresAt': tempOA.GetAccessTokenExpriesAt(),
                'type': tempOA.type,
            })
            print('InitAccessToken New User added to AuthManager. ID="{}"'.format(ID))
            user = self.GetUserByID(ID)
            if callback and user:
                callback(user)
            ret = {
                'message': 'The user was created using the existing tokens'
            }
            if initAccessToken or initRefreshToken:
                ret['user'] = user
            return ret

        userCode = tempOA.GetUserCode()

        @Wait(0)
        def Loop(tempOA=tempOA, ID=ID):
            while not tempOA.DeviceCodeExpired():
                time.sleep(tempOA.Interval)

                accessToken = tempOA.GetAccessToken()
                if accessToken is not None:
                    self._pv.Set(ID, {
                        'accessToken': tempOA.GetAccessToken(),
                        'refreshToken': tempOA.GetRefreshToken(),
                        'expiresAt': tempOA.GetAccessTokenExpriesAt(),
                        'type': tempOA.type,
                    })
                    print('New User added to AuthManager. ID="{}"'.format(ID))
                    if callback:
                        callback(self.GetUserByID(ID))
                    break
            else:
                print('Device Code Expired. User was NOT created.')
                if callback:
                    callback(None)

        print('Go to "{}" and enter code "{}"'.format(tempOA.VerificationURI, userCode))
        return {
            'verification_uri': tempOA.VerificationURI,
            'user_code': userCode,
            'message': tempOA.message,
        }

    def CreateUserFromPersonalityFile(self, personalityFile, ID=None):
        d = json.load(open(personalityFile, mode='rb'))
        self.print('d=', d)

        if 'ms' in d['calendar']['type']:
            self._microsoftClientID = d['calendar']['o365_clientinfo']['client_id']
            self._microsoftTenantID = d['calendar']['o365_clientinfo']['tenant_id']
            d = self.CreateNewUser(
                ID=ID or d['calendar']['o365_clientinfo']['credential_name'],
                authType='Microsoft',
                initAccessToken=d['calendar']['o365_clientinfo']['access_token'],
                initRefreshToken=d['calendar']['o365_clientinfo']['refresh_token'],
            )
        else:
            raise NotImplementedError('TODO')

        return d['user']


if __name__ == '__main__':
    def TestMicrosoft():
        try:
            import creds
        except:
            creds = object()
            creds.clientID = '459ac21c-adde-45a5-abf3-85d757ba2fdf'
            creds.tenantID = '30f18c78-f7ab-4851-9759-88950e65dc4b'

        import webbrowser

        MY_ID = '3888'
        TYPE = 'Microsoft'

        authManager = AuthManager(
            microsoftClientID=creds.clientID,
            microsoftTenantID=creds.tenantID,
        )

        user = authManager.GetUserByID(MY_ID)
        print('user=', user)
        if user is None:
            print('No user exists for ID="{}"'.format(MY_ID))

            d = authManager.CreateNewUser(MY_ID, authType=TYPE)
            webbrowser.open(d.get('verification_uri'))
            print('User Code=', d.get('user_code'))

        while True:
            user = authManager.GetUserByID(MY_ID)
            if user is None:
                time.sleep(1)
            else:
                break
        print('user=', user)


    def TestGoogle():
        import creds
        import webbrowser
        MY_ID = '3888'
        JSON_PATH = 'google_test_creds.json'
        TYPE = 'Google'

        authManager = AuthManager(
            googleJSONpath=JSON_PATH,
            debug=True
        )

        user = authManager.GetUserByID(MY_ID)

        if user is None:
            print('No user exists for ID="{}"'.format(MY_ID))

            d = authManager.CreateNewUser(MY_ID, authType=TYPE)
            webbrowser.open(d.get('verification_uri'))
            print('User Code=', d.get('user_code'))

        while True:
            user = authManager.GetUserByID(MY_ID)
            if user is None:
                time.sleep(1)
            else:
                break
        print('user=', user)


    # TestMicrosoft()
    TestGoogle()
