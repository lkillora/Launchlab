import numpy as np
import hashlib
import base58
from glob import glob
import pandas as pd
from dotenv import load_dotenv
import os
import requests
import json
import time
from datetime import datetime
import pickle
import string
import re
from collections import Counter
from solana.constants import BPF_LOADER_PROGRAM_ID
from solana.rpc.api import Client
from solders.pubkey import Pubkey
from solders.solders import Signature, Keypair, Pubkey
from solana.rpc.async_api import AsyncClient
from solders.message import Message
from solders.transaction import Transaction
from solana.rpc.types import TxOpts
import http.client, urllib.parse

load_dotenv(".env", override=True)
HELIUS_API_KEY = os.environ['HELIUS_API_KEY']
QUICKNODE_SOL_DEVNET_RPC = os.environ['QUICKNODE_SOL_DEVNET_RPC']
SYS_CLOCK_PROGRAM_ID = Pubkey.from_string('SysvarC1ock11111111111111111111111111111111')
HELIUS_MAINNET_RPC = os.environ['HELIUS_RPC']
HELIUS_API_KEY = os.environ['HELIUS_API_KEY']
HELIUS_RPC = os.environ['HELIUS_RPC']
PRIVKEY = os.environ['PRIVKEY']
PINATA_API_KEY = os.environ['PINATA_API_KEY']
PINATA_API_SECRET = os.environ['PINATA_API_SECRET']
PINATA_JWT_TOKEN = os.environ['PINATA_JWT_TOKEN']
DEPLOYER_PRIVKEY = os.environ['DEPLOYER_PRIVKEY']
SIGNER = Keypair().from_base58_string(os.environ['OLD_PRIVKEY'])
JITO_TIP_ACCOUNT = Pubkey.from_string('96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5')
PUSHOVER_API_KEY = os.environ['MY_PUSHOVER_API_KEY']
PUSHOVER_USER_KEY = os.environ['MY_WORK_PUSHOVER_USER_KEY']

def strip_filename(f):
    return '.'.join(os.path.basename(f).split('.')[:-1])

def fetch_txs_for_acc(account, before=None, source=None, tx_type=None, mainnet=False):
    if mainnet:
        rpc = "https://api.helius.xyz"
    else:
        rpc = "https://api-devnet.helius.xyz"
    url = f"{rpc}/v0/addresses/{account}/transactions?api-key={HELIUS_API_KEY}"
    params = {}
    if before is not None:
        params['before'] = before
    if source is not None:
        params['source'] = source
    if tx_type is not None:
        params['type'] = tx_type

    response = requests.get(url=url, params=params)
    print(f'Response: {response.status_code}')
    txs = json.loads(response.text)
    return txs


def fetch_all_txs_for_acc(account, before=None, source=None, tx_type=None, mainnet=False, limit=10):
    all_txs = []
    txs = fetch_txs_for_acc(account, before=before, source=source, tx_type=tx_type, mainnet=mainnet)
    i = 0
    while i <= limit:
        if type(txs) == dict:
            last_sig = txs['error'].split()[-1].replace('.', '')
            print(f"Failed on request {i} out of {limit}")
        else:
            all_txs.extend(txs)
            last_sig = txs[-1]['signature']
            print(f"{datetime.fromtimestamp(min([t['timestamp'] for t in txs]))} on request {i} out of {limit}")
        time.sleep(1)
        i += 1
        txs = fetch_txs_for_acc(account, before=last_sig, source=source, tx_type=tx_type, mainnet=mainnet)
    return all_txs


def fetch_all_signatures(address, before=None, mainnet=True, limit=10, rpc=None, sleep_time=1, start_time=datetime.now() - pd.Timedelta(days=60)):
    if rpc is None:
        if mainnet:
            rpc = f"https://mainnet.helius-rpc.com/?api-key={HELIUS_API_KEY}"
        else:
            rpc = f"https://devnet.helius-rpc.com/?api-key={HELIUS_API_KEY}"
    client = Client(rpc)
    all_signatures = []
    i = 0
    earliestTime = int(time.time())
    if start_time is not None:
        startTime = int(start_time.timestamp())

    while i <= limit or startTime < earliestTime:
        if sleep_time > 0:
            time.sleep(sleep_time)
        response = client.get_signatures_for_address(Pubkey.from_string(address), before=before, limit=1000)
        signatures = response.value
        if signatures:
            all_signatures.extend([json.loads(s.to_json()) for s in signatures])
            before = signatures[-1].signature
            earliestTime = signatures[-1].block_time
            if i % 10 == 0:
                print(f'Request {i + 1} for {address}: {len(signatures)} results at {datetime.fromtimestamp(earliestTime)}')
        else:
            print(f'Request {i + 1} for {address}: 0 results')
            break
        i += 1
    print(f"Fetched {len(all_signatures)} transaction signatures for {address}")
    return all_signatures


def fetch_program_accounts(program, mainnet=False):
    if mainnet:
        rpc = f"https://mainnet.helius-rpc.com/?api-key={HELIUS_API_KEY}"
    else:
        rpc = f"https://devnet.helius-rpc.com/?api-key={HELIUS_API_KEY}"
    response = requests.post(
        rpc,
        headers={"Content-Type": "application/json"},
        json={"jsonrpc": "2.0", "id": "1", "method": "getProgramAccounts", "params": [program, {"encoding": "jsonParsed"}]}
    )
    result = response.json()['result']
    return result



def fetch_transaction_api(sig, mainnet=True, commitment='confirmed'):
    if mainnet:
        url = f"https://api.helius.xyz/v0/transactions?api-key={HELIUS_API_KEY}"
    else:
        url = f"https://api-devnet.helius.xyz/v0/transactions?api-key={HELIUS_API_KEY}"

    data = {
        "transactions": [sig]
    }
    response = requests.post(url=url, json=data, headers={"Content-Type": "application/json"}, params={"commitment": commitment})
    tx = json.loads(response.text)[0]
    return tx


def fetch_transactions_api(account, before=None, source=None, mainnet=False):
    if mainnet:
        url = f"https://api.helius.xyz/v0/addresses/{account}/transactions?api-key={HELIUS_API_KEY}"
    else:
        url = f"https://api-devnet.helius.xyz/v0/addresses/{account}/transactions?api-key={HELIUS_API_KEY}"

    params = {}
    if before is not None:
        params['before'] = before
    if source is not None:
        params['source'] = source
    response = requests.get(url=url, params=params)
    txs = json.loads(response.text)
    return txs


def pickle_file(path, obj=None, read=True):
    if read:
        with open(path, 'rb') as f:
            return_obj = pickle.load(f)
            return return_obj
    else:
        with open(path, 'wb') as f:
            pickle.dump(obj, f)

def json_file(path, obj=None, read=True):
    if read:
        with open(path, 'r') as f:
            return_obj = json.load(f)
            return return_obj
    else:
        with open(path, 'w') as f:
            json.dump(obj, f)


def fetch_transaction_rpc(sig, rpc, commitment="finalized"):
    response = requests.post(
        rpc,
        headers={"Content-Type": "application/json"},
        json={"jsonrpc": "2.0", "id": 1, "method": "getTransaction",
              "params": [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0, "commitment": commitment}]}
    )
    tx = response.json()['result']
    return tx


def return_data_of_acc(acc, rpc):
    client = Client(rpc)
    response = client.get_account_info(Pubkey.from_string(acc))
    data = response.value.data
    return data


def fetch_program_data_account(program, rpc):
    response = requests.post(
        rpc,
        headers={"Content-Type": "application/json"},
        json={"jsonrpc": "2.0", "id": "1", "method": "getAccountInfo", "params": [program, {"encoding": "jsonParsed"}]}
    )
    result = response.json()['result']
    program_data_account = result['value']['data']['parsed']['info']['programData']
    return program_data_account


def find_meaningful_text(program_data_acc, cleaned_program_text):
    # Instructions
    instructions = []
    for m in re.finditer('Instruction: ((?:(?!Instruction)[A-Za-z0-9])*)', cleaned_program_text):
        instructions.append(m.group())

    # .rs files
    rs_files = set()
    for m in re.finditer('[a-z]*\\.rs', cleaned_program_text):
        rs_files.add(m.group())
    rs_files = list(rs_files)

    # .rs files
    key_rs_files = set()
    for m in re.finditer(r'programs\S*?\.rs', cleaned_program_text):
        key_rs_files.add(m.group())
    key_rs_files = list(key_rs_files)

    # program folder name
    programs = set()
    for m in re.finditer('programs/[^/]+/', cleaned_program_text):
        programs.add(m.group())
    programs = list(programs)

    summary = {'program_data_acc': program_data_acc, 'programs': programs, 'instructions': instructions, 'key_rs_files': key_rs_files, 'rs_files': rs_files}
    return summary


def retrieve_program_text(program_data_acc, rpc=QUICKNODE_SOL_DEVNET_RPC, sleep_time=0, mainnet=False):
    program_bytes = return_data_of_acc(program_data_acc, rpc)
    cleaned_program_data = bytes(c for c in program_bytes if c in bytes(string.printable, 'ascii'))
    cleaned_program_text = cleaned_program_data.decode("utf-8", errors="ignore")
    summary = find_meaningful_text(program_data_acc, cleaned_program_text)
    cluster = 'mainnet' if mainnet else 'devnet'
    with open(f'./data/program_text/{program_data_acc}_{cluster}.txt', 'w') as f:
        f.write(cleaned_program_text)
    with open(f'./data/program_text_summary/{program_data_acc}_{cluster}.json', 'w') as f:
        json.dump(summary, f, indent=4)
    if sleep_time > 0:
        time.sleep(sleep_time)


def retrieve_program_text_from_prog(program, rpc=QUICKNODE_SOL_DEVNET_RPC, sleep_time=0, mainnet=False):
    program_data_acc = fetch_program_data_account(program, rpc)
    retrieve_program_text(program_data_acc, rpc, sleep_time, mainnet=mainnet)


def find_matches_and_surrounding_characters(text, pattern, lookahead=100, lookback=0, ignore_case_override=None):
    if ignore_case_override is None:
        if pattern.lower() == pattern:
            text = text.lower()
    else:
        if ignore_case_override:
            text = text.lower()

    matches = list(re.finditer(pattern, text))
    output_text = f''
    for i in range(len(matches)):
        prev_chars = text[max(0, matches[i].start() - lookback):matches[i].start()]
        next_chars = text[matches[i].end():matches[i].end() + lookahead]
        output_text += f"{prev_chars}||{matches[i].group(0)}||{next_chars}\n"
    return output_text


def load_jsons(path, include_name=True):
    files = glob(path)
    loaded = []
    for f in files:
        temp_loaded = json_file(f, read=True)
        if include_name:
            temp_loaded['name'] = strip_filename(f)
        loaded.append(temp_loaded)
    return loaded


def convert_to_hex(string: str) -> str:
    return string.encode('utf-8').hex()


def discriminate(hex_str: str) -> str:
    leng = int(np.ceil(len(hex_str) / 2))
    return convert_int_to_le_hex(leng).ljust(8, "0")


def encode_string(string: str) -> str:
    hex_str = convert_to_hex(string)
    return discriminate(hex_str) + hex_str

def encode_metadata(name: str, symbol: str, uri: str) -> str:
    return encode_string(name) + encode_string(symbol) + encode_string(uri)

def convert_hex_to_base58(hex):
    return base58.b58encode(bytes.fromhex(hex)).decode()

def convert_le_hex_to_int(hex):
    return int.from_bytes(bytes.fromhex(hex), byteorder='little')

def convert_int_to_le_hex(integer, length = None):
    if length is None:
        length = (integer.bit_length() + 7) // 8 or 1
    return integer.to_bytes(length, byteorder='little').hex()

def convert_base58_to_hex(b58_str):
    return base58.b58decode(b58_str).hex()

def convert_hex_to_text(hex):
    return bytes.fromhex(hex).decode("utf-8", errors="ignore")

def get_anchor_discriminator(instruction_name: str) -> bytes:
    """
    Returns the 8-byte discriminator used by Anchor for a given instruction.
    """
    preimage = f"global:{instruction_name}"
    hash_bytes = hashlib.sha256(preimage.encode('utf-8')).digest()
    return hash_bytes[:8]



async def simulate_tx(instructions, signers, mainnet=False):
    if mainnet:
        rpc = f"https://mainnet.helius-rpc.com/?api-key={HELIUS_API_KEY}"
    else:
        rpc = f"https://devnet.helius-rpc.com/?api-key={HELIUS_API_KEY}"
    async with AsyncClient(rpc) as client:
        blockhash_resp = await client.get_latest_blockhash()
        blockhash = blockhash_resp.value.blockhash

        message = Message(instructions, signers[0].pubkey())
        tx = Transaction(signers, message, blockhash)

        simulation_resp = await client.simulate_transaction(tx)
        return simulation_resp


async def send_tx(instructions, signers, simulate_first=False, mainnet=False):
    if mainnet:
        rpc = f"https://mainnet.helius-rpc.com/?api-key={HELIUS_API_KEY}"
    else:
        rpc = f"https://devnet.helius-rpc.com/?api-key={HELIUS_API_KEY}"
    async with AsyncClient(rpc) as client:
        blockhash_resp = await client.get_latest_blockhash()
        blockhash = blockhash_resp.value.blockhash

        message = Message(instructions, signers[0].pubkey())
        tx = Transaction(signers, message, blockhash)

        if simulate_first:
            simulation_resp = await client.simulate_transaction(tx)
            if simulation_resp.value.err is None:
                response = await client.send_transaction(tx)
                print(f'Transaction sent! Response: {response}')
            else:
                print("Transaction simulation failed:", simulation_resp)

        opts = TxOpts(skip_preflight=True)
        response = await client.send_transaction(tx, opts=opts)
        print(response)
        return response


def send_pushover_alert(message, priority=0, user_key=PUSHOVER_USER_KEY):
    if priority == 2:
        sound = "persistent"
    else:
        sound = "tugboat"

    conn = http.client.HTTPSConnection("api.pushover.net:443")
    conn.request("POST", "/1/messages.json",
                 urllib.parse.urlencode({
                     "token": PUSHOVER_API_KEY,
                     "user": user_key,
                     "message": message,
                     "priority": priority,
                     "retry": 30,
                     "expire": 600,
                     "sound": sound,
                 }), {"Content-type": "application/x-www-form-urlencoded"})
    print(conn.getresponse().read())
    return None
