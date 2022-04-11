#!/usr/bin/python3

import bech32
import cbor2
import hashlib
from typing import List, NamedTuple
from blockfrost import BlockFrostApi, ApiError, ApiUrls
from httplib2 import Response
import requests
import argparse
from time import sleep
from fireblocks_sdk import *

apiSecret = open('/Users/slavaserebriannyi/api_keys/fireblocks_secret.key', 'r').read()
apiKey = 'f704b8d8-29d2-5ce9-9e15-4a3ad29e585a' #mainnet
#apiKey = 'd5ce7e80-d6a5-598a-88a3-037660377627' #testnet
fireblocks = FireblocksSDK(apiSecret, apiKey)


BIP_44_CONSTANT = 44
ADA_COIN_TYPE = 1815
ADA_TEST_COIN_TYPE = 1
CHANGE_INDEX = 0
PERMENANT_ACCOUNT_INDEX = 0
CHIMERIC_INDEX = 2
DEFAULT_NATIVE_TX_FEE = 300000  # Over-estimate (0.3 ADA)
DEPOSIT_AMOUNT = 2000000
TX_TTL_SECS = 7200  # 2 Hours
MIN_UTXO_VALUE_ADA_ONLY = 1000000


STAKE_KEY_REGISTRATION = 0
STAKE_KEY_DE_REGISTRATION = 1
DELEGATION = 2


class CardanoUTxO(NamedTuple):
    tx_hash: bytes
    index_in_tx: int
    native_amount: int


class CardanoWitness(NamedTuple):
    pub_key: bytes
    sig: bytes


class CardanoRewardWithdrawal(NamedTuple):
    certificate: bytes
    reward: int # in LoveLace.


class CardanoStaking(object):
    def __init__(self, vault_account: int, base_address: str, mainnet: bool, api: BlockFrostApi, api_key: str) -> None:
        if vault_account < 0:
            raise Exception(f'Invalid account value of {vault_account}')

        self.__account = vault_account
        self.__mainnet = mainnet
        self.__api = api
        self.__base_address = base_address
        self.__api_key = api_key

        if mainnet:
            self.__coin_type = ADA_COIN_TYPE
        else:
            self.__coin_type = ADA_TEST_COIN_TYPE


    @staticmethod
    def __blake_hash(payload: bytes, digest_size=28) -> bytes:
        h = hashlib.blake2b(digest_size=digest_size)
        h.update(payload)
        return h.digest()


    @staticmethod
    def __get_signing_payload(serialized_tx: bytes) -> bytes:
        return CardanoStaking.__blake_hash(serialized_tx, 32)


    @staticmethod
    def __embed_sigs_in_tx(deserialized_tx_payload: dict, sigs: List[CardanoWitness]) -> bytes:
        witnesses_arr = []
        for sig in sigs:
            witnesses_arr.append([sig.pub_key, sig.sig])
        deserialized = [deserialized_tx_payload, {0: witnesses_arr}, None]
        return cbor2.dumps(deserialized)


    @staticmethod
    def __serialize_certificate(certificate: bytes) -> dict:
        certificate_arr = [0, certificate]
        return certificate_arr


    def __get_input(self, min_input_amount: int) -> CardanoUTxO:
        utxos = self.__api.address_utxos(address=self.__base_address)
        for utxo in utxos:
            if (len(utxo.amount) == 1):
                amount = utxo.amount[0]
                print("%s:%s: %s %s" % (utxo.tx_hash, utxo.output_index, amount.quantity, amount.unit))
                if (amount.unit == 'lovelace' and int(amount.quantity) > min_input_amount):
                    return CardanoUTxO(tx_hash=bytearray.fromhex(utxo.tx_hash), index_in_tx=utxo.output_index, native_amount=int(amount.quantity))

    def __wait_for_transaction_confirmation(self, txid):
        tx = fireblocks.get_transaction_by_id(txid)
        while tx['status'] not in (TRANSACTION_STATUS_CONFIRMED, TRANSACTION_STATUS_CANCELLED, TRANSACTION_STATUS_REJECTED, TRANSACTION_STATUS_FAILED):
            print(f"Transaction still in status {tx['status']}")
            if tx['status'] == TRANSACTION_STATUS_CONFIRMING or tx['status'] == TRANSACTION_STATUS_COMPLETED:
                break
            sleep(3)
            tx = fireblocks.get_transaction_by_id(txid)


        print(f"Transaction status is now {tx['status']}, will stop following it.")
        return tx
    
    def __send_for_signing(self, txHash: str) -> List[CardanoWitness]:
        if OPERATION == 'register':
            note = f"Going to register the staking key for vault account {VAULT_ACCOUNT}"
        elif OPERATION == 'delegate':
            note = f"Going to delegate ADA from vault account {VAULT_ACCOUNT} to the following pool: {args.pool_id}"
        elif OPERATION == 'deregister':
            note = f"Going to deregister the staking key for vault account {VAULT_ACCOUNT}"
        elif OPERATION == 'withdraw-rewards':
            note = f'Going to withdraw available rewards for vault account {VAULT_ACCOUNT}'

        tx_res = fireblocks.create_raw_transaction(
            asset_id = 'ADA' if NETWORK == 'mainnet' else 'ADA_TEST',
            source = TransferPeerPath('VAULT_ACCOUNT', VAULT_ACCOUNT),
            raw_message=RawMessage(
                messages = [
                    UnsignedMessage(
                        content = txHash,
                        bip44addressIndex=0
                    ),
                    UnsignedMessage(
                        content = txHash,                        
                        bip44addressIndex=CHIMERIC_INDEX
                    )
                ],
            ),
            note=note   
            )
        print(tx_res)

        sig_res = self.__wait_for_transaction_confirmation(tx_res['id'])
        
        pub_key1 = sig_res['signedMessages'][0]['publicKey']
        pub_key2 = sig_res['signedMessages'][1]['publicKey']
        
        sig1 = sig_res['signedMessages'][0]['signature']['fullSig']
        sig2 = sig_res['signedMessages'][1]['signature']['fullSig']
        
        wit1 = CardanoWitness(bytearray.fromhex(pub_key1), bytearray.fromhex(sig1))
        wit2 = CardanoWitness(bytearray.fromhex(pub_key2), bytearray.fromhex(sig2))

        return [wit1, wit2]



    def __get_ttl(self) -> int:
        currentSlot = self.__api.block_latest().slot
        print ("Current slot: %d" % currentSlot)
        return currentSlot + TX_TTL_SECS


    def __query_account_rewards(self) -> Response:
        stake_address = self.__get_stake_address_from_base_address()

        account_rewards = api.account_rewards(
        stake_address=stake_address,
        count=20,
        gather_pages=True, # will collect all pages
        )

        account_withdrawals = api.account_withdrawals(
        stake_address=stake_address,
        count=20,
        gather_pages=True, # will collect all pages
        )

        sum_rewards = 0
        for reward in account_rewards:
            sum_rewards += int(reward.amount)

        sum_withdrawals = 0
        for withdrawals in account_withdrawals:
            sum_withdrawals += int(withdrawals.amount)

        available_rewards = sum_rewards - sum_withdrawals
        if (available_rewards < 0):
            raise Exception(f'Invalid available_rewards:{available_rewards}')
        return available_rewards, account_rewards, account_withdrawals


    def print_account_rewards(self) -> None:
        available_rewards, account_rewards, account_withdrawals = self.__query_account_rewards()

        print("rewards:")
        for reward in account_rewards:
            print("pool-id:%s amount:%s epoch:%d" % (reward.pool_id, reward.amount, reward.epoch))

        print("withdrawals:")
        for withdrawals in account_withdrawals:
            print("hash:%s amount:%s" % (withdrawals.tx_hash, withdrawals.amount))

        print("Total available rewards amount: %d Lovelace" % (available_rewards))


    def __get_withdrawals(self, max_withdrawal: int) -> [CardanoRewardWithdrawal, int]:
        available_rewards, _, _ = self.__query_account_rewards()
        certificate = bytearray(self.__get_certificate_from_base_address())

        print("Total available rewards is: %d Lovelace" % available_rewards)

        reward_amount = available_rewards
        if reward_amount == 0:
            print('No rewards to withdraw')
            return
        elif reward_amount > max_withdrawal:
            reward_amount = max_withdrawal

        return CardanoRewardWithdrawal(bytes(self.__stake_address_bytes_prefix() + certificate), reward_amount), reward_amount


    def __submit_tx(self, tx: bytes) -> None:
        try:
            headers = {'project_id': self.__api_key,
            'User-Agent': 'blockfrost-python 0.4.2',
            'Content-Type': 'application/cbor'
            }

            # Blockfrost python client expects to receive a file constructed by cardano-cli
            # Therefore we submit via requests, and should submit to different url than ApiUrls' values.
            BASE_URL = "https://cardano-mainnet.blockfrost.io/api/v0" if self.__mainnet else "https://cardano-testnet.blockfrost.io/api/v0"

            url = "%s/tx/submit" % BASE_URL
            res = requests.post(
                url=url,
                headers=headers,
                data=tx)
            print("Tx submission res: %s:%s" % (res.status_code, res.content))
        except Exception as e:
            print('Fail sending submitting tx to blockfrost: %s' % str(e))


    def __add_registration(self, certificate: bytes) -> list:
        decoded_cert = self.__serialize_certificate(certificate=certificate)
        registration = [STAKE_KEY_REGISTRATION, decoded_cert]
        return registration


    def __add_de_registration(self, certificate: bytes) -> list:
        decoded_cert = self.__serialize_certificate(certificate=certificate)
        registration = [STAKE_KEY_DE_REGISTRATION, decoded_cert]
        return registration


    def __stake_address_bytes_prefix(self) -> bytes:
        return bytearray.fromhex('e1' if self.__mainnet else 'e0')


    def __get_stake_address_hrp(self) -> str:
        return 'stake' if self.__mainnet else 'stake_test'


    def __get_address_hrp(self) -> str:
        return 'addr' if self.__mainnet else 'addr_test'


    def __encode_stake_address(self, decoded_address: bytes) -> str:
        return bech32.bech32_encode(
            hrp=self.__get_stake_address_hrp(),
            data=bech32.convertbits(decoded_address, 8, 5, True)
        )

    def __get_stake_address_from_certificate(self, certificate: bytes) -> str:
        return self.__encode_stake_address(self.__stake_address_bytes_prefix() + certificate)


    def __get_certificate_from_base_address(self) -> bytes:
        decoded = self.__decode_address(encoded_address=self.__base_address)
        return decoded[29:]


    def __get_stake_address_from_base_address(self) -> str:
        certificate = self.__get_certificate_from_base_address()
        return self.__get_stake_address_from_certificate(certificate=certificate)


    def __decode_address(self, encoded_address: str) -> bytes:
        if f'{self.__get_address_hrp()}1' not in encoded_address:
            raise Exception(f'Address {encoded_address} is invalid (use Shelley-era addresses)')

        _, decoded = bech32.bech32_decode(bech=encoded_address)
        return bytes(bech32.convertbits(decoded, 5, 8, False))


    def __pool_delegation(self, certificate: bytes, pool_id: str) -> dict:
        serialized_certificate = self.__serialize_certificate(certificate=certificate)
        delegation = [DELEGATION, serialized_certificate, bytearray.fromhex(pool_id)]
        return delegation


    def __serialize_withdrawals(self, withdrawals: List[CardanoRewardWithdrawal]) -> dict:
        withdrawal_dict = {}
        for withdrawal in withdrawals:
            withdrawal_dict[withdrawal.certificate] = withdrawal.reward
        return withdrawal_dict


    def __sign(self, message : bytes, messageDict: dict) -> bytes:
        txHash = self.__get_signing_payload(message)
        signatures = self.__send_for_signing(txHash.hex())
        print("Done set for signing in __sign")
        return self.__embed_sigs_in_tx(messageDict, signatures)


    def __build_payload(self, to_address: str, net_amount: int, tx_inputs: List[CardanoUTxO],
                        fee_amount: int, ttl: int, certificates = None, withdrawals = None) -> [bytes, dict]:
        inputs_arr = []
        for tx_input in tx_inputs:
            inputs_arr.append([tx_input.tx_hash, tx_input.index_in_tx])

        outputs_arr = [[self.__decode_address(to_address), net_amount]]

        deserialized = {
            0: inputs_arr,
            1: outputs_arr,
            2: fee_amount,
            3: ttl,
            }

        if certificates:
            deserialized[4] = certificates

        if withdrawals:
            deserialized[5] = withdrawals

        return cbor2.dumps(deserialized), deserialized


    def register(self) -> None:
        min_input_amount = DEPOSIT_AMOUNT + DEFAULT_NATIVE_TX_FEE
        input = self.__get_input(min_input_amount=min_input_amount)
        net_amount = input.native_amount - DEFAULT_NATIVE_TX_FEE - DEPOSIT_AMOUNT

        certificate = self.__get_certificate_from_base_address()
        registration_certificate = self.__add_registration(certificate=certificate)

        message, messageDict = self.__build_payload(
            to_address=self.__base_address,
            net_amount=net_amount,
            tx_inputs=[input],
            fee_amount=DEFAULT_NATIVE_TX_FEE,
            ttl=self.__get_ttl(),
            certificates=[registration_certificate]
            )
        full_tx = self.__sign(message=message, messageDict=messageDict)

        self.__submit_tx(full_tx)


    def delegate(self, pool_id: str) -> None:
        min_input_amount = MIN_UTXO_VALUE_ADA_ONLY + DEFAULT_NATIVE_TX_FEE
        input = self.__get_input(min_input_amount=min_input_amount)
        net_amount = input.native_amount - DEFAULT_NATIVE_TX_FEE

        certificate = self.__get_certificate_from_base_address()
        delegation = self.__pool_delegation(certificate=certificate, pool_id=pool_id)

        message, messageDict = self.__build_payload(
            to_address=self.__base_address,
            net_amount=net_amount,
            tx_inputs=[input],
            fee_amount=DEFAULT_NATIVE_TX_FEE,
            ttl=self.__get_ttl(),
            certificates=[delegation]
            )

        full_tx = self.__sign(message=message, messageDict=messageDict)

        self.__submit_tx(full_tx)


    def deregister(self) -> None:
        min_input_amount = MIN_UTXO_VALUE_ADA_ONLY + DEFAULT_NATIVE_TX_FEE
        input = self.__get_input(min_input_amount=min_input_amount)
        certificate = self.__get_certificate_from_base_address()
        withdrawal, rewards_amount = self.__get_withdrawals(max_withdrawal=float('inf'))
        net_amount = input.native_amount - DEFAULT_NATIVE_TX_FEE + DEPOSIT_AMOUNT + rewards_amount

        withdrawals_dict = self.__serialize_withdrawals(withdrawals=[withdrawal])

        registration = self.__add_de_registration(certificate=certificate)
        certificate_arr = [registration]

        message, messageDict = self.__build_payload(
            to_address=self.__base_address,
            net_amount=net_amount,
            tx_inputs=[input],
            fee_amount=DEFAULT_NATIVE_TX_FEE,
            ttl=self.__get_ttl(),
            certificates=certificate_arr,
            withdrawals=withdrawals_dict
            )

        full_tx = self.__sign(message=message, messageDict=messageDict)

        self.__submit_tx(full_tx)



    def withdaw_rewards(self, limit: int) -> None:
        if limit is None:
            limit = float('inf')
        min_input_amount = MIN_UTXO_VALUE_ADA_ONLY + DEFAULT_NATIVE_TX_FEE
        input = self.__get_input(min_input_amount=min_input_amount)
        withdrawal, rewards_amount = self.__get_withdrawals(max_withdrawal=limit)
        net_amount = input.native_amount - DEFAULT_NATIVE_TX_FEE + rewards_amount

        withdrawals_dict = self.__serialize_withdrawals(withdrawals=[withdrawal])

        message, messageDict = self.__build_payload(
            to_address=self.__base_address,
            net_amount=net_amount,
            tx_inputs=[input],
            fee_amount=DEFAULT_NATIVE_TX_FEE,
            ttl=self.__get_ttl(),
            withdrawals=withdrawals_dict
            )

        full_tx = self.__sign(message=message, messageDict=messageDict)

        self.__submit_tx(full_tx)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='staking.py', description='SDK for staking Cardano with Fireblocks')
    parser.add_argument('-v', '--vault-account', help='Vault Account ID', type=int, required=True)
    parser.add_argument('-k', '--key', help='Blockfrost API Key', required=True)
    parser.add_argument( '-n', '--network', help='Testnet(testnet) or Mainnet (mainnet)', required = True)

    subparsers = parser.add_subparsers(title='operation', dest='operation')
    _ = subparsers.add_parser('register', help='Register staking certificate')
    _ = subparsers.add_parser('deregister', help='Deregister staking certificate')
    _ = subparsers.add_parser('query-rewards', help='Print account rewards')
    withdraw_parser = subparsers.add_parser('withdraw-rewards', help='Withdraw staking rewards')
    withdraw_parser.add_argument('-l', '--limit' , help='Maximum amount to withdraw. If is not specified - withdraw all', type=int, required=False)
    delegate_parser = subparsers.add_parser('delegate', help='Delegate to a stake pool')
    delegate_parser.add_argument('-p', '--pool-id' , help='Pool ID that you want to delegate to', required=True)

    args = parser.parse_args()

    if args.network == 'mainnet':
        is_mainnet = True
    else:
        is_mainnet = False
    
    global VAULT_ACCOUNT 
    global OPERATION
    global POOL_ID
    global NETWORK

    VAULT_ACCOUNT = str(args.vault_account)
    OPERATION = str(args.operation)
    POOL_ID = str(args.pool_id if OPERATION == "delegate" else "")
    NETWORK = str(args.network)

    asset_id = 'ADA' if is_mainnet else 'ADA_TEST'
    vault_addresses = fireblocks.get_deposit_addresses(args.vault_account, asset_id)
    
    if len(vault_addresses) != 2:
        raise Exception('Please make sure to create a new vault account with permanent address only')
    else:
        if vault_addresses[0]["addressFormat"] == "BASE":
            base_address = vault_addresses[0]["address"]
        else:
            base_address = vault_addresses[1]["address"]

    base_url = ApiUrls.mainnet.value if is_mainnet else ApiUrls.testnet.value


    api = BlockFrostApi(
        project_id=args.key,
        base_url=base_url,
    )

    wallet = CardanoStaking(
        vault_account=args.vault_account,
        mainnet=is_mainnet,
        base_address = base_address,
        api=api,
        api_key=args.key
        )

    try:
        if args.operation == 'register':
            wallet.register()
        elif args.operation == 'delegate':
            wallet.delegate(pool_id=args.pool_id)
        elif args.operation == 'query-rewards':
            wallet.print_account_rewards()
        elif args.operation == 'deregister':
            wallet.deregister()
        elif args.operation == 'withdraw-rewards':
            wallet.withdaw_rewards(limit=args.limit)
        else:
            print ("Unknown operation: %s" % args.operation)
            parser.print_help()


    except Exception as e:
        print(e)