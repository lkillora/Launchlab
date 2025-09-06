import time
import base58
from nacl.public import PublicKey
from solders.pubkey import Pubkey
from spl.token.instructions import get_associated_token_address, create_associated_token_account
from solders.keypair import Keypair
from solders.instruction import Instruction, AccountMeta
from solders.system_program import transfer, TransferParams
from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
from solfunctions import SIGNER, JITO_TIP_ACCOUNT, fetch_transaction_rpc, fetch_transaction_api
from solfunctions import simulate_tx, send_tx, HELIUS_API_KEY, PINATA_JWT_TOKEN
from borsh_construct import CStruct, String as BorshString, U64, U8
from spl.token.instructions import sync_native, SyncNativeParams
import requests
from io import BytesIO

LAUNCHLAB = Pubkey.from_string('LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj')
platform_config = Pubkey.from_string('FfYek5vEz23cMkWsdJwG2oa6EphsvXSHrGpdALN4g6W1')
wsol = Pubkey.from_string('So11111111111111111111111111111111111111112')
usd1 = Pubkey.from_string('USD1ttGY1N17NEEHLmELoaybftRBUSErhqYiQzvEmuB')



def upload_to_ipfs_using_pinata(image_url='https://imgcdn.stablediffusionweb.com/2024/5/27/aa11456f-4077-449a-a53f-ef00ae832f5e.jpg', name='Eagle', symbol='EAGLE', description="America, fuck yeah"):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/114.0.0.0 Safari/537.36"
    }
    if 'http' in image_url:
        response = requests.get(image_url, headers=headers)
        response.raise_for_status()
        image_blob = BytesIO(response.content)
    else:
        with open(image_url, "rb") as f:
            image_blob = f.read()
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {
        "Authorization": f'Bearer {PINATA_JWT_TOKEN}',
    }
    files = {"file": ('image.jpg', image_blob)}
    files["pinataOptions"] = (None, json.dumps({"cidVersion": 0}))
    response = requests.post(url, files=files, headers=headers)
    image_uri = f'https://ipfs.io/ipfs/{response.json()["IpfsHash"]}'
    print(f'Image URI: {image_uri}')

    metadata = {
        'name': name,
        'symbol': symbol,
        'description': description,
        'image': image_uri,
        "showName": True,
    }
    url = "https://api.pinata.cloud/pinning/pinJsonToIPFS"
    response = requests.post(url, json=metadata, headers=headers)
    metadata_uri = f'https://ipfs.io/ipfs/{response.json()["IpfsHash"]}'
    print(f'Metadata URI: {metadata_uri}')
    return metadata_uri


def get_new_global_config(sig='4gXUjPi5EZtABocMUoHSM4YcdoCJZZUUFEaCQsmoJLLVajaZXS2UPnpyHK5B7Yn2RYEEX4skzFQA5XdZ4SG7raho'):
    tx = fetch_transaction_api(sig, commitment="confirmed")
    config = None
    for i in tx['instructions']:
        for j in i['innerInstructions']:
            if j['programId'] == str(LAUNCHLAB) and base58.b58decode(j['data']).hex().startswith('c9cff3724b6f2fbd'):
                config = Pubkey.from_string(j['accounts'][1])
    return config


async def create_launchlab_token(
        global_config,
        platform_config = platform_config,
        production = True,
        signer = SIGNER

):
    if global_config is None:
        global_config = Pubkey.from_string('6s1xP3hpbAfFoNtUNF8mfHsjr2Bd97JxFJRWLbL6aHuX')

    if production:
        quote_mint = usd1
        tip_amount = 50_000_000
        amount_in = 3_000_000_000
        mint = Keypair.from_base58_string('2DngoxKF7bHUHjiAMFCVvCpfDNWVfR28M5ivEzyzYqBkoPW4tMJiAcmqjKUStWRAW45hfLuou5jbyaNZ45axCkgw')
        name = 'Eagle'
        symbol = 'EAGLE'
        uri = 'https://ipfs.io/ipfs/QmQPLHfG5BHWnftpJTWz4SPEebGZtr5vt9NgMiFpEUKxLs'

    else:
        quote_mint = wsol
        tip_amount = 5_000_000
        amount_in = 10
        mint = Keypair()
        name = 'The Golden Twap'
        symbol = 'TWAP'
        uri = 'https://ipfs.io/ipfs/QmWzLJYR7fWckWvX1y3KUKtBXBEamGxQqbHju5YXqV4Lat'

    mint_pubkey = mint.pubkey()
    platform_auth = Pubkey.from_string('WLHv2UAZm6z4KyaaELi5pjdbJh6RESMva1Rnn8pJVVh')
    launchpad_prog = LAUNCHLAB
    pool_state, _ = Pubkey.find_program_address([b'pool', mint_pubkey.__bytes__(), quote_mint.__bytes__()], launchpad_prog)
    base_vault, _ = Pubkey.find_program_address([b'pool_vault', pool_state.__bytes__(), mint_pubkey.__bytes__()], launchpad_prog)
    quote_vault, _ = Pubkey.find_program_address([b'pool_vault', pool_state.__bytes__(), quote_mint.__bytes__()], launchpad_prog)
    metaplex_program = Pubkey.from_string('metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s')
    token_program = Pubkey.from_string('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')
    system_program = Pubkey.from_string('11111111111111111111111111111111')
    rent_program = Pubkey.from_string('SysvarRent111111111111111111111111111111111')
    event_auth = Pubkey.from_string('2DPAtwB8L12vrMRExbLuyGnC7n2J5LNoZQSejeQGpwkr')
    metaplex_pda, _ = Pubkey.find_program_address([b'metadata', metaplex_program.__bytes__(), mint_pubkey.__bytes__()], metaplex_program)

    creation_accounts = [
        [signer.pubkey(), True, True], # payer
        [signer.pubkey(), True, True], # creator
        [global_config, False, False], # global_config
        [platform_config, False, False], # platform_config
        [platform_auth, False, False], # platform_auth
        [pool_state, False, True], # pool_state
        [mint_pubkey, True, True], # mint
        [quote_mint, False, False], # quote_mint
        [base_vault, False, True], # base_vault
        [quote_vault, False, True], # quote_vault
        [metaplex_pda, False, True], # metaplex_pda
        [token_program, False, False], # base token program
        [token_program, False, False], # quote token program
        [metaplex_program, False, False], # metaplex_program
        [system_program, False, False], # system_program
        [rent_program, False, False], # rent_program
        [event_auth, False, False], # event_auth
        [launchpad_prog, False, False], # launchpad_prog
    ]

    # MintParams
    # CurveParams
    # VestingParams
    # AmmCreatorFeeOn - enum - migrate to cpmm, creator fee on quote token (0) or both token (1)

    creation_prefix = "4399af27da102620" #"afaf6d1f0d989bed06"
    NameSymbolUriSchema = CStruct(
        "decimals" / U8,
        "name" / BorshString,
        "symbol" / BorshString,
        "uri" / BorshString
    )
    token_name_encoded = NameSymbolUriSchema.build({
        "decimals": 6,
        "name": name,
        "symbol": symbol,
        "uri": uri
    })
    creation_intermediate = token_name_encoded.hex()
    migration_threshold = "001265ca13" if quote_mint == wsol else "00dd0ee902"
    creation_suffix = f"000080c6a47e8d03000078c5fb51d10200{migration_threshold}0000000100000000000000000000000000000000000000000000000000"
    creation_data = creation_prefix + creation_intermediate + creation_suffix

    creation_ix = Instruction(
            launchpad_prog,
            bytes.fromhex(creation_data),
            tuple(AccountMeta(pubkey=k[0], is_signer=k[1], is_writable=k[2]) for k in creation_accounts),
    )

    base_user = get_associated_token_address(signer.pubkey(), mint_pubkey)
    quote_user = get_associated_token_address(signer.pubkey(), quote_mint)

    platform_vault, _ = Pubkey.find_program_address([platform_config.__bytes__(), quote_mint.__bytes__()], launchpad_prog)
    creator_vault, _ = Pubkey.find_program_address([signer.pubkey().__bytes__(), quote_mint.__bytes__()], launchpad_prog)

    buy_accounts = [
        [signer.pubkey(), True, True], # payer
        [platform_auth, False, False], # platform_auth
        [global_config, False, False], # global_config
        [platform_config, False, False], # platform_config
        [pool_state, False, True], # pool_state
        [base_user, False, True],  # base_user
        [quote_user, False, True],  # quote_user
        [base_vault, False, True], # base_vault
        [quote_vault, False, True], # quote_vault
        [mint_pubkey, True, True], # mint
        [quote_mint, False, False], # quote_mint
        [token_program, False, False], # base token program
        [token_program, False, False], # quote token program
        [event_auth, False, False], # event_auth
        [launchpad_prog, False, False], # launchpad_prog
        [system_program, False, False], # launchpad_prog
        [platform_vault, False, True],  # base_user
        [creator_vault, False, True],  # quote_user
    ]

    buy_exact_in_prefix = "faea0d7bd59c13ec"
    BuyExactInSchema = CStruct(
        "amount_in" / U64,
        "minimum_amount_out" / U64,
        "share_fee_rate" / U64
    )
    buy_exact_in_encoded = BuyExactInSchema.build({
        "amount_in": amount_in,
        "minimum_amount_out": 0,
        "share_fee_rate": 0
    })
    buy_exact_in_data = buy_exact_in_prefix + buy_exact_in_encoded.hex()

    buy_ix = Instruction(
            launchpad_prog,
            bytes.fromhex(buy_exact_in_data),
            tuple(AccountMeta(pubkey=k[0], is_signer=k[1], is_writable=k[2]) for k in buy_accounts),
    )

    create_ata_mint_ix = create_associated_token_account(
        payer=signer.pubkey(),
        owner=signer.pubkey(),
        mint=mint_pubkey
    )
    wsol_ata = get_associated_token_address(signer.pubkey(), quote_mint)
    create_ata_quote_ix = create_associated_token_account(
        payer=signer.pubkey(),
        owner=signer.pubkey(),
        mint=wsol
    )
    transfer_wsol_ix = transfer(
        TransferParams(
            from_pubkey=SIGNER.pubkey(),
            to_pubkey=wsol_ata,
            lamports=amount_in  # Amount of SOL to wrap
        )
    )
    sync_native_ix = sync_native(
       SyncNativeParams(account=wsol_ata, program_id=token_program)
    )

    priority_fee_ix = set_compute_unit_price(10000)
    cu_ix = set_compute_unit_limit(400000)

    jito_tip_ix = transfer(
        TransferParams(
            from_pubkey=signer.pubkey(),
            to_pubkey=JITO_TIP_ACCOUNT,
            lamports=tip_amount
        )
    )

    instructions = [
        jito_tip_ix,
        cu_ix,
        priority_fee_ix,
        creation_ix,
        create_ata_mint_ix,
        # create_ata_quote_ix,
        # transfer_wsol_ix,
        # sync_native_ix,
        buy_ix
    ]
    signers = [signer, mint]
    response = await send_tx(instructions, signers=signers, mainnet=True)
    # response = await simulate_tx(instructions, signers=signers, mainnet=True)
    return response

