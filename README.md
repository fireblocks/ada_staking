# Ada Staking


### About
This repository containes the SDK for staking Cardano in Fireblocks.
NOTE: This SDK uses Fireblocks RAW signing, kindly note that running this SDK is on your own responsibility. Fireblocks team is here for any assistance and guidance.


## Usage
#### Before You Begin
Make sure you have the credentials for Fireblocks API Services. Otherwise, please contact Fireblocks support for further instructions on how to obtain your API credentials.

#### Requirements
Python and pip installed

#### Installation
`Clone the repository:
git clone https://github.com/fireblocks/ada_staking.git`

Run:
`pip3 install -r requirements.txt`

Usage: 
`staking.py -v <VAULT_ACCOUNT_ID> -k <BLOCKFROST_API_KEY> -n {testnet, mainnet} {register,deregister,query-rewards,withdraw-rewards,delegate}`

If the operation is `delegate`, please make sure to add `-p <STAKING_POOL_ID>`
