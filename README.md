# Ada Staking

Clone the repository 

Run: python3 install -r requirements.txt

usage: staking.py [-h] -v VAULT_ACCOUNT -a ADDRESS -k KEY {register,deregister,query-rewards,withdraw-rewards,delegate} ...

staking FB cardano wallet.

optional arguments:
  -h, --help            show this help message and exit
  -v VAULT_ACCOUNT, --vault-account VAULT_ACCOUNT
                        Vault account
  -a ADDRESS, --address ADDRESS
                        Wallet permanent address
  -k KEY, --key KEY     Blockfrost api key

operation:
  {register,deregister,query-rewards,withdraw-rewards,delegate}
    register            register certificate
    deregister          deregister
    query-rewards       Print account rewards
    withdraw-rewards    withdraw rewards
    delegate            delegate to stake pool
