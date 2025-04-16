#!/usr/bin/python3

"""
Conway DRep delegation using pycardano with Fireblocks signing.
This handles Conway era governance requirements for Cardano.
"""

import argparse
import time
from typing import Tuple
from fireblocks_sdk import *
from pycardano import (
    Address, TransactionInput, TransactionOutput,
    Transaction, TransactionBody, TransactionWitnessSet,
    VerificationKey, VerificationKeyWitness, StakeCredential, DRepKind,
    BlockFrostChainContext, Value, VoteDelegation, DRep
)
from blockfrost import BlockFrostApi

# Constants
CHIMERIC_INDEX = 2
DEFAULT_FEE = 1000000  # 1 ADA


def wait_for_transaction_confirmation(fireblocks, txid):
    """Wait for a Fireblocks transaction to be confirmed"""
    tx = fireblocks.get_transaction_by_id(txid)
    while tx['status'] not in (
    TRANSACTION_STATUS_CONFIRMED, TRANSACTION_STATUS_CANCELLED, TRANSACTION_STATUS_REJECTED, TRANSACTION_STATUS_FAILED):
        print(f"Transaction still in status {tx['status']}")
        if tx['status'] == TRANSACTION_STATUS_CONFIRMING or tx['status'] == TRANSACTION_STATUS_COMPLETED:
            break
        time.sleep(3)
        tx = fireblocks.get_transaction_by_id(txid)

    print(f"Transaction status is now {tx['status']}, will stop following it.")
    return tx


def fireblocks_sign_tx(fireblocks, tx_hash_hex, vault_account, asset_id, operation="DRep delegation") -> Tuple[
    dict, dict]:
    """Send transaction for signing with Fireblocks"""

    note = f"Cardano delegate to DRep {operation} for vault account {vault_account}"

    tx_res = fireblocks.create_raw_transaction(
        asset_id=asset_id,
        source=TransferPeerPath('VAULT_ACCOUNT', vault_account),
        raw_message=RawMessage(
            messages=[
                UnsignedMessage(
                    content=tx_hash_hex
                ),
                UnsignedMessage(
                    content=tx_hash_hex,
                    bip44change=CHIMERIC_INDEX
                )
            ],
        ),
        note=note
    )
    print(f"Created Fireblocks transaction: {tx_res['id']}")

    sig_res = wait_for_transaction_confirmation(fireblocks, tx_res['id'])

    return sig_res


def get_suitable_utxo(api, address, min_amount):
    """Find a suitable UTXO to use as input"""
    utxos = api.address_utxos(address=address)
    for utxo in utxos:
        if len(utxo.amount) == 1:  # Only consider UTXOs with just ADA (no tokens)
            amount = utxo.amount[0]
            if amount.unit == 'lovelace' and int(amount.quantity) > min_amount:
                print(f"Selected UTXO: {utxo.tx_hash}:{utxo.output_index} with {amount.quantity} lovelace")
                return {
                    "tx_hash": utxo.tx_hash,
                    "index": utxo.output_index,
                    "amount": int(amount.quantity)
                }

    return None


def main():
    parser = argparse.ArgumentParser(description='Delegate to a DRep in Conway era with PyCardo and Fireblocks')
    parser.add_argument('-v', '--vault-account', type=int, required=True, help='Fireblocks vault account ID')
    parser.add_argument('-k', '--key', required=True, help='Blockfrost API key')
    parser.add_argument('-n', '--network', required=True, choices=['mainnet', 'testnet'],
                        help='Network (mainnet or testnet)')
    parser.add_argument('-a', '--api-key', required=True, help='Fireblocks API key')
    parser.add_argument('-s', '--api-secret', required=True, help='Path to Fireblocks API secret key file')
    parser.add_argument('-d', '--drep-action', default='always-abstain',
                        choices=['always-abstain', 'always-no-confidence', 'custom-drep'], help='DRep action')
    parser.add_argument('-i', '--drep-id', help='Custom DRep ID (hex format, required if --drep-action is custom-drep)')

    args = parser.parse_args()

    if args.drep_action == 'custom-drep' and not args.drep_id:
        parser.error("--drep-id is required when --drep-action is custom-drep")

    api_secret = open(args.api_secret, 'r').read()
    fireblocks = FireblocksSDK(api_secret, args.api_key)

    base_url =  "https://cardano-mainnet.blockfrost.io/api" if args.network == 'mainnet' else "https://cardano-preprod.blockfrost.io/api"
    context = BlockFrostChainContext(args.key, base_url=base_url)

    asset_id = 'ADA' if args.network == 'mainnet' else 'ADA_TEST'
    vault_addresses = fireblocks.get_deposit_addresses(args.vault_account, asset_id)

    if vault_addresses[0]["addressFormat"] == "BASE":
        base_address_str = vault_addresses[0]["address"]
    else:
        base_address_str = vault_addresses[1]["address"]

    print(f"Using base address: {base_address_str}")

    base_address = Address.from_primitive(base_address_str)

    blockfrost_api = BlockFrostApi(
        project_id=args.key,
        base_url=base_url
    )

    # Find a suitable UTXO
    utxo_data = get_suitable_utxo(blockfrost_api, base_address_str, DEFAULT_FEE*2)  # At least 2 ADA
    if not utxo_data:
        print(f"No suitable UTXOs found with at least {DEFAULT_FEE} lovelace")
        return

    # Create transaction input and output
    tx_hash = utxo_data["tx_hash"]
    tx_idx = utxo_data["index"]
    print(f"Found an input with an amount of {utxo_data['amount']}")
    amount = utxo_data["amount"]

    # Create proper TransactionInput and UTxO object
    tx_input = TransactionInput.from_primitive([tx_hash, tx_idx])
    fee = DEFAULT_FEE  # Use a fixed fee of 1 ADA
    change_amount = amount - fee
    change_output = TransactionOutput(base_address, Value(change_amount))
    stake_hash = base_address.staking_part

    # Create the stake credential directly from the VerificationKeyHash
    stake_credential = StakeCredential(stake_hash)

    # Create vote delegation certificate with proper DRep format
    if args.drep_action == 'always-abstain':
        print("Creating Always Abstain vote delegation")
        drep = DRep(DRepKind.ALWAYS_ABSTAIN)
    elif args.drep_action == 'always-no-confidence':
        print("Creating Always No Confidence vote delegation")
        drep = DRep(DRepKind.ALWAYS_NO_CONFIDENCE)
    else:
        print(f"Creating custom DRep vote delegation to: {args.drep_id}")
        drep_bytes = bytes.fromhex(args.drep_id)
        drep = DRep(DRepKind.KEY_HASH, drep_bytes)

    cert = VoteDelegation(stake_credential, drep)

    # Create transaction body
    tx_body = TransactionBody(
        inputs=[tx_input],
        outputs=[change_output],
        fee=fee,
        certificates=[cert]
    )

    unsigned_tx = Transaction(tx_body, TransactionWitnessSet())
    tx_hash_hex = unsigned_tx.transaction_body.hash().hex()

    # Sign with Fireblocks
    print("Sending transaction for signing with Fireblocks...")
    sig_res = fireblocks_sign_tx(
        fireblocks,
        tx_hash_hex,
        args.vault_account,
        asset_id
    )

    if len(sig_res['signedMessages']) != 2:
        print("Error: Did not get 2 signatures")
        return

    payment_vkey = bytes.fromhex(sig_res['signedMessages'][0]['publicKey'])
    payment_signature = bytes.fromhex(sig_res['signedMessages'][0]['signature']['fullSig'])

    stake_vkey = bytes.fromhex(sig_res['signedMessages'][1]['publicKey'])
    stake_signature = bytes.fromhex(sig_res['signedMessages'][1]['signature']['fullSig'])

    # Create proper VerificationKey objects
    payment_vk = VerificationKey(payment_vkey)
    stake_vk = VerificationKey(stake_vkey)

    # Create witnesses with the proper keys
    witness1 = VerificationKeyWitness(payment_vk, payment_signature)
    witness2 = VerificationKeyWitness(stake_vk, stake_signature)

    # Set up the witness set
    witness_set = TransactionWitnessSet()
    witness_set.vkey_witnesses = [witness1, witness2]

    # Create signed transaction
    signed_tx = Transaction(unsigned_tx.transaction_body, witness_set, auxiliary_data=None)
    print("Submitting transaction...")
    try:
        res = context.submit_tx(signed_tx)
        print("Transaction submitted successfully!")
        print("Result:", res)
    except Exception as e:
        print(f"Error submitting transaction: {e}")


if __name__ == "__main__":
    main()