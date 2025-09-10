import requests
import json

envs = [
    "https://api-test.myx.cash",
    "https://api-test.myx.cash",
    "https://api-beta.myx.finance",
    "https://api.myx.finance"
]

for env in envs:
    headers = {'Authorization': 'Bearer ecdsa-1.0xA58CA0709F9CC27526cc51A03C6605f1C0f10077-jODZMYLwGeITWEpE-1759788065.0xf6866ad1a95dbfaa52c8173785a6c024f87e44c13de8a4b62dc79fdad87ee00209f3b5e28cf9db975eff8bfef6435a4af75ee54163ee22a626e52561881fb8d81b'}
    response = requests.get(env+'/v2/vip/info', headers=headers)
    if response.status_code != 200:
        print(f'{env} failed')
    else:
        print(json.dumps(response.json(), indent=4))


