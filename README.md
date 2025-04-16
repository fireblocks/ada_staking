# Ada Staking


### About
This repository contains the SDK for staking Cardano in Fireblocks by using one of Fireblocks' supported staking providers.

NOTE: This SDK uses Fireblocks RAW signing.
Kindly note that running this SDK is on your own responsibility.
Fireblocks team is here for any assistance and guidance.


## Usage
#### Before You Begin
Make sure you have the credentials for Fireblocks API Services. Otherwise, please contact Fireblocks support for further instructions on how to obtain your API credentials.

#### Requirements
- Python and pip installed
- RAW Signing enabled
- Transaction Authorization Policy is configured with a RAW signing rule
- Fireblocks API credentials
- BlockFrost API Key

#### Installation
Clone the repository:

`git clone https://github.com/fireblocks/ada_staking.git`

Update the following parameters in the `staking.py` file:
1. `apiKey` - your Fireblocks API key
2. `apiSecret` - the path to your API secret key file

Run:
`pip3 install -r requirements.txt`

Usage: 
`python3 staking.py -v <VAULT_ACCOUNT_ID> -k <BLOCKFROST_API_KEY> -n {testnet, mainnet} {register,deregister,query-rewards,withdraw-rewards,delegate}`

If the operation is `delegate`, please make sure to add `-p <STAKING_POOL_ID>`

### Delegate to a [DRep](https://docs.gov.tools/cardano-govtool/faqs/what-is-a-drep)

Before withdrawing your assets, please make sure that you delegated to a DRep. If you did not, please run:

`python3 delegate_to_drep.py -v <VAULT_ACCOUNT_ID> -k <BLOCKFROST_API_KEY> -n {testnet, mainnet} -a <FIREBLOCKS_API_KEY> -s <FIREBLOCKS_SECRET_KEY_PATH>`

Once the account is delegated to a DRep, you can withdraw the staking rewards without any waiting period.

**NOTE:** Please make sure that you have at least one UTXO on your account with an amount of >2 ADA.