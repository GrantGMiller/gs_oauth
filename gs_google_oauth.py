import json
import time
import requests
from urllib.parse import urlencode

# based on the steps here:https://developers.google.com/identity/protocols/OAuth2ForDevices

try:
    from persistent_variables import PersistentVariables as PV
    import aes_tools
    from extronlib.system import File, Wait, ProgramLog

except Exception as e:
    print(e)
    pass

DEBUG = True
oldPrint = print
if DEBUG is False:
    print = lambda *a, **k: None


class OauthDeviceCode:
    def __init__(self, jsonPath, initAccessToken=None, initRefreshToken=None,
                 initAccessTokenExpiresAt=None):
        with open(jsonPath, mode='rt') as file:
            self._creds = json.loads(file.read())

        self._session = requests.session()

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

    def _InitVerificationURI(self):
        authURL = '{}?{}'.format(
            self._creds['installed']['auth_uri'],
            urlencode({
                'client_id': self._creds['installed']['client_id'],
                'redirect_uri': self._creds['installed']['redirect_uris'][-1],
                'scope': ' '.join([
                    'https://www.googleapis.com/auth/calendar',
                ]),
                'access_type': 'offline',
                'response_type': 'code',
            })
        )
        self._verificationURI = authURL
        return authURL

    def _DoRequest(self, method, url, data=None, params=None):
        print('_DoRequests(', method, url, data, params)
        resp = self._session.request(method=method, url=url, data=data, params=params)

        print('resp.text=', resp.text)
        print('resp.status_code=', resp.status_code)
        print('resp.reason=', resp.reason)

        return resp

    def __init_old__(self, clientID, tenantID, initAccessToken=None, initRefreshToken=None,
                     initAccessTokenExpiresAt=None):
        self._clientID = clientID
        self._tenantID = tenantID

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

    def GetUserCode(self):
        data = {
            'client_id': self._creds['installed']['client_id'],
            'scope': ' '.join([
                    'https://www.googleapis.com/auth/calendar',
                ]),
        }
        url = 'https://accounts.google.com/o/oauth2/device/code'
        resp = requests.post(url, data=data)
        print('resp=', resp.json())
        self._verificationURI = resp.json().get('verification_url')
        self._userCode = resp.json().get('user_code')
        self._deviceCode = resp.json().get('device_code')
        self._interval = resp.json().get('interval')
        self._deviceCodeExpiresAt = time.time() + resp.json().get('expires_in')
        self._lastRequest = time.time()
        print('')
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
        print('GetAccessToken()')
        if time.time() - self._lastRequest < self._interval:
            # only make request once per "interval"
            return self._accessToken

        if self._accessToken:
            # we already received an access token previously
            if time.time() > self._accessTokenExpiresAt:
                print('The accessToken is expired, use the refreshToken to get a new one')
                url = 'https://oauth2.googleapis.com/token'
                data = {
                    'client_id': self._creds['installed']['client_id'],
                    'client_secret': self._creds['installed']['client_secret'],
                    'refresh_token': self._refreshToken,
                    'grant_type': 'refresh_token',
                }
                try:
                    resp = requests.post(url, data)
                    self._lastRequest = time.time()
                    print('Refresh Token request complete')
                    print('resp.json()=', resp.json())
                    self._accessToken = resp.json().get('access_token')
                    self._refreshToken = resp.json().get('refresh_token', self._refreshToken)# google uses the same refresh token?
                    self._accessTokenExpiresAt = time.time() + resp.json().get('expires_in')
                except Exception as e:
                    ProgramLog(str(e), 'error')
                return self._accessToken
            else:
                print('The access token will expire in {} seconds'.format(
                    int(self._accessTokenExpiresAt - time.time())))
                print('The access token is still good, return it.')
                return self._accessToken
        else:
            # This is the first time we are retrieving an access token
            url = 'https://oauth2.googleapis.com/token'
            # url = 'http://grant-miller.com'
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
            print('resp=', resp.json())
            self._accessToken = resp.json().get('access_token', None)
            self._refreshToken = resp.json().get('refresh_token', None)
            if self._accessToken:
                self._accessTokenExpiresAt = time.time() + resp.json().get('expires_in', None)
            return self._accessToken


class User:
    def __init__(self, ID, authManagerParent):
        self._ID = ID

        data = authManagerParent.Get(self)
        self._oa = OauthDeviceCode(
            clientID=authManagerParent.ClientID,
            tenantID=authManagerParent.TenantID,
            initAccessToken=data.get('accessToken', None),
            initRefreshToken=data.get('refreshToken', None),
            initAccessTokenExpiresAt=data.get('expiresAt', None),
        )
        self._emailAddress = data.get('emailAddress', None)
        self._authManagerParent = authManagerParent

    def __str__(self):
        return '<User: ID={}, EmailAddress={}>'.format(self.ID, self.EmailAddress)

    @property
    def ID(self):
        return self._ID

    @property
    def Data(self):
        return {
            'accessToken': self._oa.GetAccessToken(),
            'refreshToken': self._oa.GetRefreshToken(),
            'expiresAt': self._oa.GetAccessTokenExpriesAt(),
            'emailAddress': self._emailAddress
        }

    @property
    def EmailAddress(self):
        if self._emailAddress is None:
            resp = requests.get(
                # 'https://graph.microsoft.com/v1.0/me',
                'https://outlook.office.com/api/v2.0/me',
                headers={
                    'Authorization': 'Bearer {}'.format(self._oa.GetAccessToken()),
                    'Content-Type': 'application/json',
                }
            )
            print('resp.json()=', resp.json())
            print('resp.status_code=', resp.status_code)
            if resp.status_code == 200:
                self._emailAddress = resp.json().get('EmailAddress', None)
                self._authManagerParent.Update(self)

        return self._emailAddress

    def GetAcessToken(self):
        return self._oa.GetAccessToken()


class AuthManager:
    def __init__(self, clientID, tenantID):
        self._clientID = clientID
        self._tenantID = tenantID
        self._pv = PV('OAuth.json', fileClass=File if DEBUG else aes_tools.File)
        '''
        Data stored like this:
        {
        str(rfidBadgeNumber): {
            'accessToken': str(),
            'refreshToken': str(),
            'expiresAt': float() # time.time()
            'emailAddress': str(email)
            }
        }
        '''

    @property
    def ClientID(self):
        return self._clientID

    @property
    def TenantID(self):
        return self._tenantID

    def Update(self, userObj):
        self._pv.Set(userObj.ID, userObj.Data)

    def Get(self, userObj):
        return self._pv.Get(userObj.ID, {})

    def GetUserByID(self, ID):
        print('self._pv.Get()=', self._pv.Get())
        if ID in self._pv.Get():
            return User(
                ID,
                authManagerParent=self,
            )
        else:
            return None  # no user exist, you can use CreateNewUser if you like

    def CreateNewUser(self, ID):
        tempOA = OauthDeviceCode(self._clientID, self._tenantID)
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
                    })
                    print('New User added to AuthManager. ID="{}"'.format(ID))
                    break
            else:
                print('Device Code Expired. User was NOT created.')

        return {
            'verification_uri': tempOA.VerificationURI,
            'user_code': userCode,
        }


if __name__ == '__main__':
    # Test OauthDeviceCode() class
    import creds
    import webbrowser

    JSON_PATH = 'client_secret_673364926560-srmglql2fn27lfk6rea3oear6itdlojn.apps.googleusercontent.com.json'

    oa = OauthDeviceCode(JSON_PATH)
    ret = oa.GetUserCode()
    print('ret=', ret)
    webbrowser.open(oa.VerificationURI)
    while True:
        time.sleep(1)
        ret = oa.GetAccessToken()
