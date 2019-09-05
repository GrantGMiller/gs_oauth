from requests_oauthlib import OAuth2Session
import creds
from gs_tools import GetRandomHash
import requests
from urllib.parse import urlencode

clientID = '459ac21c-adde-45a5-abf3-85d757ba2fdf'
clientSecret = '@E_RmbI2LKYuQvhK5y=au.DXqig9ndD4'

# oauth = OAuth2Session(
#     client_id=clientID,
#     redirect_uri='https://login.microsoftonline.com/common/oauth2/nativeclient',
#     scope='https://outlook.office.com'
# )
#
# token = oauth.fetch_token(
#     # endpoints found at https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Overview/appId/459ac21c-adde-45a5-abf3-85d757ba2fdf/isMSAApp/
#     token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
#     username=creds.username,
#     password=creds.password,
#     client_id=clientID,
#     client_secret=clientSecret,
#     #authorization_response=None,#'https://grant-miller.com/test_endpoint?code={}&state={}'.format(GetRandomHash(8), GetRandomHash(8)),
#     code=GetRandomHash(8),
#
# )

######################################################
'''
OpenID method

Send the customer to the "url".
User authenticates on microsoftonline.com.
Microsoft server redirects the users browser to the "redirect_uri" includes the "id_token" in the body

'''
# sesh = requests.session()
#
# data={
#         'client_id': clientID,
#         'response_type': 'id_token',
#         #'redirect_uri': 'https://login.microsoftonline.com/common/oauth2/nativeclient',
#         #'redirect_uri': 'https://grant-miller.com/test_endpoint',
#         'redirect_uri': 'http://localhost:5000/auth_callback',
#         'response_mode': 'form_post',
#         'scope': 'openid',
#         'state': GetRandomHash(8),
#         'nonce': GetRandomHash(8),
#     }
# print('data=', data)
#
# url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?{}'.format(urlencode(data)),
#
# print('url=', url)
#
# # example return values
# id_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImllX3FXQ1hoWHh0MXpJRXN1NGM3YWNRVkduNCJ9.eyJhdWQiOiI0NTlhYzIxYy1hZGRlLTQ1YTUtYWJmMy04NWQ3NTdiYTJmZGYiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vMzBmMThjNzgtZjdhYi00ODUxLTk3NTktODg5NTBlNjVkYzRiL3YyLjAiLCJpYXQiOjE1NjYyMzQyOTAsIm5iZiI6MTU2NjIzNDI5MCwiZXhwIjoxNTY2MjM4MTkwLCJhaW8iOiJBVFFBeS84TUFBQUFjdTlQL1J4TitvUVRySkM5QVJCQk8vbHp0QlFJVUR4SVcycFF0NDRRYzNjNnkyV1AwL3VQSHlCWVhNdXkzYnhrIiwibm9uY2UiOiI2OGUwZWFmZCIsInN1YiI6IlZLTDlWVFY4QlhRQWpxZmxQQ3UyWlhpS3dOWGhxb0pCQW11UXktbGJreWMiLCJ0aWQiOiIzMGYxOGM3OC1mN2FiLTQ4NTEtOTc1OS04ODk1MGU2NWRjNGIiLCJ1dGkiOiJKem5XczNjRUZFeW1qRllSeTJHRkFBIiwidmVyIjoiMi4wIn0.u2j8LaYVlpMjjLvqk9OxBvr6cpz-KRmeP0k7XXP7dEPJssRK9T0SYj4-WT14RI7KZO-_bjC7KRDT20M8C4WSXelqNELGDCv4qOlzMFIo2WX8I8UaQ_jP4un92VyggErh143OhYh3Cgn6YUo6Tp1GjmXsNHorjjveBqAKIeYS2Xj13oVfDxWb0Rbjv4xymb6-Qc23gEmru79OM4Yg2od4AiXrreWx7lHBrwBZmZuKhfkY7BWKVAJfinChcasByYRN3NryJaWfroa90ti7zWkCPXRaD5tXgjAHdaUv2Je0ZrQR8qwh1a3YUCXBbahCyFyvzjaICiJ-eJNTfc_QlC2GdQ'
# state = '3352eab5'
# session_state = 'c972210c-f50f-4c9d-9503-11c622b88040'

'''
ROPC method

ROPC = Resource Owner Password Credential
https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc

'''

data = {
    'client_id': clientID,
    'scope': 'https://outlook.office.com/Calendars.ReadWrite offline_access',
    'username': creds.username,
    'password': creds.password,
    'grant_type': 'password',
}
tenant = 'organizations'  # 'organizations' or 'common' or 'consumers' or GUID

sesh = requests.session()
resp = sesh.post(
    url='https://login.microsoftonline.com/{}/oauth2/v2.0/token'.format(tenant),
    data=data,

)
print('resp.headers=', resp.headers)
print('resp.cookies=', resp.cookies)
print('resp.text=', resp.text)

# print('token=', token)
