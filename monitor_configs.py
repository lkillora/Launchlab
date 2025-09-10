

import requests
import hashlib
import time
from dotenv import load_dotenv
import http.client, urllib.parse
import os
import logging

CHECK_INTERVAL = 1
BACKOFF_MULTIPLIER = 2
MAX_BACKOFF_INTERVAL = 120

load_dotenv(".env", override=True)
pushover_api_key = os.environ['MY_PUSHOVER_API_KEY']
pushover_user_key = os.environ['MY_WORK_PUSHOVER_USER_KEY']


def send_pushover_alert(message, priority=0, user_key=pushover_user_key):
    if priority == 2:
        sound = "persistent"
    else:
        sound = "tugboat"

    conn = http.client.HTTPSConnection("api.pushover.net:443")
    conn.request("POST", "/1/messages.json",
                 urllib.parse.urlencode({
                     "token": pushover_api_key,
                     "user": user_key,
                     "message": message,
                     "priority": priority,
                     "retry": 30,
                     "expire": 600,
                     "sound": sound,
                 }), {"Content-type": "application/x-www-form-urlencoded"})
    print(conn.getresponse().read())
    return None


def detect_config_added():

    check_interval = CHECK_INTERVAL
    while True:
        response = requests.get("https://launch-mint-v1.raydium.io/main/platforms-v2")
        for site in response.json()['data']['data']:
            if 'america.fun' in site['web'].lower():
                send_pushover_alert(f'America.fun added {site}', priority=2)
                raise Exception('America.fun added site')
        else:
            check_interval = CHECK_INTERVAL
        time.sleep(check_interval)


if __name__ == "__main__":
    detect_config_added()

    """
    nohup python3 monitor_configs.py > monitor_configs.log 2>&1 &
    nohup python3 detector_boros.py > boros.log 2>&1 &
    """
