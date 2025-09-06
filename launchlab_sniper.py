import asyncio
import websockets
import json
from dotenv import load_dotenv
import os
import sys
import traceback
from solders.solders import Keypair
from launchlab import LAUNCHLAB, create_launchlab_token, get_new_global_config
from solfunctions import SIGNER, HELIUS_API_KEY, send_pushover_alert

WS_URL = f'wss://mainnet.helius-rpc.com/?api-key={HELIUS_API_KEY}'
RAYDIUM_MULTISIG = 'EXZY7FPccNuEvgHZMCMpww2Fen8oLWBSJzdgCsX3Djwm'
FETCH_GLOBAL_CONFIG = True



async def process_message(message):
    json_message = json.loads(message)

    sig = ''
    jsonmessage = ''

    try:
        if 'params' in json_message:
            tx = json_message['params']['result']['value']
            logs = tx['logs']
            sig = tx['signature']

            try:
                for log in logs:
                    if 'Instruction: CreateConfig' in log:
                        try:
                            if FETCH_GLOBAL_CONFIG:
                                global_config = get_new_global_config(sig)
                            else:
                                global_config = None
                            send_response1 = await create_launchlab_token(global_config=global_config, signer=SIGNER, production=True)
                            if send_response1 is not None:
                                print(f'SEND RESPONSE1: {send_response1}')
                                send_pushover_alert(f'SNIPED! {send_response1}', priority=2)
                                print(f'sig: {sig}')
                                print(f'logs: {logs}')
                                sys.exit(1)
                        except Exception as e:
                            send_pushover_alert(f'FAILED TO SNIPE! on {sig} because {e} {traceback.print_exc()}', priority=2)
                send_pushover_alert(f'NEW MULTSIG TX: https://solscan.io/tx/{sig}', priority=2)

            except Exception as e:
                jsonmessage = json_message
                send_pushover_alert(f'FAILED SNIPED INSIDE {e} {sig} {str(jsonmessage)}', priority=2)
                print(f"FAILED TO SNIPE: {e}\n{json_message}")

    except Exception as e:
        jsonmessage = json_message
        send_pushover_alert(f'FAILED SNIPED OUTSIDE {e} {sig} {str(jsonmessage)}', priority=1)
        print(f"FAILED TO PARSE: {e}\n{json_message}")


# Function to send a request to the WebSocket server
async def send_request(ws):
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "logsSubscribe",
        "params": [
            {
              "mentions": [RAYDIUM_MULTISIG]
            },
            {
              "commitment": "confirmed"
            }
        ]
    }
    await ws.send(json.dumps(request))
    print("Request sent")


async def start_ping(ws):
    while True:
        await asyncio.sleep(30)  # Ping every 30 seconds
        try:
            if not ws.closed:
                await ws.ping()
                print("Ping sent")
        except Exception as e:
            print(f"Ping failed: {e}")
            break

# Function to handle WebSocket connection and message receiving
async def websocket_handler():
    while True:
        try:
            async with websockets.connect(WS_URL) as ws:
                # When the connection is open, send the request and start pinging
                print("WebSocket is open")
                await send_request(ws)

                # Start pinging the server in the background
                asyncio.create_task(start_ping(ws))

                # Handle incoming messages
                while True:
                    try:
                        message = await ws.recv()
                        await process_message(message)
                    except websockets.exceptions.ConnectionClosed:
                        print("Connection closed unexpectedly, attempting to reconnect...")
                        break  # Break out of the inner loop to reconnect
                    except Exception as e:
                        print(f"Error occurred: {e}")
                        break  # Break out of the inner loop to reconnect
        except Exception as e:
            print(f"Failed to connect or reconnect: {e}")

        # Wait for a moment before attempting to reconnect
        print("Reconnecting in 5 seconds...")
        await asyncio.sleep(0.5)  # Delay before attempting to reconnect


# Start the WebSocket connection and event loop
async def main():
    try:
        await websocket_handler()
    except Exception as e:
        print(f"Error in main loop: {e}")




# Run the event loop
if __name__ == "__main__":
    asyncio.run(main())
