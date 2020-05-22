from oauth_tools import AuthManager
import creds
import webbrowser
import time
from exchange_interface import Exchange
import datetime

MY_ID = '3888'
TYPE = 'Microsoft'

authManager = AuthManager(
    microsoftClientID=creds.clientID,
    microsoftTenantID=creds.tenantID,
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

exchange = Exchange(
    accessTokenCallback=user.GetAcessToken,
    # impersonation='rnchallwaysignage1@extron.com',
    impersonation='z-touchpanelno-confrm1.9@extron.com'
)

def NewCallback(cal, item):
    print('NewCallback(', cal, dict(item))


def ChangeCallback(cal, item):
    print('ChangeCallback(', cal, item)


def DeletedCallback(cal, item):
    print('DeletedCallback(', cal, item)


exchange.Connected = lambda _, state: print(state)
exchange.Disconnected = lambda _, state: print(state)
exchange.NewCalendarItem = NewCallback
exchange.CalendarItemChanged = ChangeCallback
exchange.CalendarItemDeleted = DeletedCallback

exchange.UpdateCalendar()

# exchange.CreateCalendarEvent(
#     subject='Test (should appear on Account Calendar) created at {}'.format(time.asctime()),
#     body='Test Body',
#     startDT=datetime.datetime.now()+datetime.timedelta(hours=1),
#     endDT=datetime.datetime.now() + datetime.timedelta(hours=2)
# )
exchange.CreateMeeting(
    subject='Test Meeting (should appear on Account Calendar) created at {}'.format(time.asctime()),
    body='Test Body',
    startDT=datetime.datetime.now()+datetime.timedelta(hours=1),
    endDT=datetime.datetime.now() + datetime.timedelta(hours=2)
)

# exchange._FindFolder()

exchange.UpdateCalendar()

print('end')
