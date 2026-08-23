# Solana Serialized Transaction Message

To create a Solana transaction using the Fordefi API, set the `details->type` field to `solana_serialized_transaction_message` and pass a serialized Solana transaction message as the `details->data` field in your request.

Solana Messages
There is an unfortunate ambiguity in the use of the term "message" in Solana.
Users typically refer to Solana messages as the equivalent of "personal messages" on EVM chains—an unstructured text blobs that users can sign with their wallet to prove possession of their private key.
Fordefi supports signing such messages with both the browser extension and the [Create Transaction API](https://docs.fordefi.com/api/openapi/transactions/create_transaction_api_v1_transactions_post#transactions/create_transaction_api_v1_transactions_post/t=request&path=&d=7/type) by setting `"type": "solana_message"`.
In contrast, a Solana (transaction) `Message` is essentially an unsigned Solana transaction.

## Integrating with Solana SDKs

### TypeScript with `solana/web3.js` v1.x

When using `solana/web3.js`version 1.x, first construct a `Message` object in one of the following ways:

- If you're using some protocol's SDK, you're likely to already have a transaction object at hand—either a [`Transaction`](https://solana-labs.github.io/solana-web3.js/v1.x/classes/Transaction.html) or a [`VersionedTransaction`](https://solana-labs.github.io/solana-web3.js/v1.x/classes/VersionedTransaction.html). In this case, you can call  [`compileMessage`](https://solana-labs.github.io/solana-web3.js/v1.x/classes/Transaction.html#compileMessage) or [`message` ](https://solana-labs.github.io/solana-web3.js/v1.x/classes/VersionedTransaction.html#message)  to obtain the underlying message.
- To construct a message directly, first construct a [TransactionMessage](https://solana-labs.github.io/solana-web3.js/v1.x/classes/TransactionMessage.html) object from a list of instructions, a recent blockhash, and a payer public key. Then use either [compileToLegacyMessage](https://solana-labs.github.io/solana-web3.js/v1.x/classes/TransactionMessage.html#compileToV0Message) or [compileToV0Message](https://solana-labs.github.io/solana-web3.js/v1.x/classes/TransactionMessage.html#compileToV0Message) to obtain a `Message` or `MessageV0` object, respectively.


Once you have a `Message` object, call [serialize](https://solana-labs.github.io/solana-web3.js/v1.x/classes/MessageV0.html#serialize) to obtain the raw bytes, encode them as base64, and use the result as the `details->data` field in your Fordefi API request.

### TypeScript with `solana/web3.js` v2

When using `solana/web3.js`version 2, given a `TransactionMessage`, call [`compileTransaction`](https://solana-labs.github.io/solana-web3.js/functions/_solana_web3_js.compileTransaction.html) to obtain a  `Transaction` object. Its ` messageBytes` field then contains the serialized transaction message. Encode it in base64 and use it as the `details->data` field in your Fordefi API request.

### Python with `solders`

When using the `solders` Python library, create a `Message` object, use `bytes` to serialize it, and encode the result in base64.

The following example shows how to create the body of the request using `solders`. After creating the body, proceed to sign and send the request like explained in [Create and Authenticate Transactions](/developers/getting-started/create-and-authenticate-transactions).

You can find additional code examples using `solders` for native SPL token and SOL transfers [here](https://github.com/FordefiHQ/api-examples/blob/main/python/simple-api-transfers/transfer_native_solana_solders.py).

```python
import base64
import json
from solders.pubkey import Pubkey
from solders.message import Message
from solders.system_program import TransferParams, transfer

sender_vault_id = "<VAULT_ID>"
sender_vault_address = Pubkey.from_string("<YOUR_VAULT_ADDRESS>") 
receiver = Pubkey.from_string("<RECEIVER_ADDRESS>")
amount_lamports = 1

# Create a transfer instruction of 1 lamport
transfer_ix = transfer(
    TransferParams(
        from_pubkey=sender_vault_address,
        to_pubkey=receiver,
        lamports=amount_lamports
    )
)
# Compile the message for a v0 transaction (with mock blockhash)
# Replace with MessageV0 for v0 message
msg = Message([transfer_ix], sender_vault_address)  

# Construct the JSON body
json_body = {
    "vault_id": sender_vault_id,
    "signer_type": "api_signer",
    "type": "solana_transaction",
    "details": {
        "type": "solana_serialized_transaction_message",
        "data": base64.b64encode(bytes(msg)).decode(),
        "chain": "solana_mainnet"
    },
}

request_body = json.dumps(json_body)

# Proceed to sign the request and send it to the API.
```

## Recent blockhash

Every Solana transaction must contain a recent blockhash—a hash of a block from the last 150 slots, which corresponds to roughly 1–1.5 minutes. (The exception is transactions that use a durable nonce, which are outside of the scope of this guide.)

When using the Fordefi API, the Fordefi server will set the recent blockhash right before the transaction is signed. This is optimal, since it makes sure that the recent blockhash is as fresh as possible before signing. (If the recent block were set by the request, a lengthy transaction-approval process might make it stale by the time the transaction is signed.) Nevertheless, when using some Solana SDKs, constructing a serialized transaction message requires specifying *some*  recent blockhash. In this case, you should set it to any value, and the Fordefi server will override it with a fresh value right before signing the transaction. The exception to this is when the transaction consists of partial signatures - that topic is coming up next.

## Fees

Solana has a [priority fee mechanism](/user-guide/manage-transactions/understand-transaction-fees/solana), and correctly setting the fee is crucial to increase the chances of the transaction being included in the blockchain.

When creating Solana transactions with the API you have two options:

- If you want to set the priority fee yourself, you can use the standard `ComputeBudget` program as part of your transaction. See the [Solana documentation](https://solana.com../user-guide/core/fees) for more information. When your transaction contains instructions that execute the `ComputeBudget` program, Fordefi will not change the priority fee that these instructions specify.
- If you want Fordefi to automatically set the priority fee for your transaction, do not include any `ComputeBudget` instructions in your transaction. Fordefi will then automatically set the priority fee of your transaction based on the current fees of the network.


## Transactions with multiple signers

Transactions of some Solana applications require multiple signatures. In such cases, the Fordefi vault is only one of the signers, and the transaction needs to be signed by additional signers.

When using Fordefi to sign transactions with multiple signers, you have three options:

- Pre-sign the transaction with the additional (non-Fordefi) signers, and pass those partial signatures as part of your request, in the `details->signatures` field. Fordefi will then provide the remaining signature and send the fully-signed transaction to the blockchain. With this option, the partial signatures in the request already bind the transaction to a particular recent blockhash and set into motion the "expiration clock" of the transaction. Any delay in signing the transaction (for example, if the policy requires a manual approval of the transaction) will likely invalidate the recent blockhash.
- Partially sign the transaction using the Fordefi API and later add the other signatures. With this approach, you will first use the Fordefi API to partially sign the transaction with the key of your Fordefi vault. Then, retrieve the partially signed transaction from the Fordefi API, add the signatures of the remaining (non-Fordefi) signers, and [manually broadcast the transaction to the blockchain](/developers/broadcast-signed-transactions). (To do that, set the transaction's "push mode" to "manual" in your request.) As in the previous approach, this approach also has the downside that the recent blockhash is fixed at the time of the first signature (Fordefi's in this case).
- Don't presign the transaction. Instead, provide the additional signing keys as part of the request, specifically in the `details->ephemeral_keys`field . Fordefi will then fix the recent blockhash right and sign the transaction on behalf of all the required signers: the Fordefi vault and the additional signers, whose keys are provided with the request. Sending private keys as part of the request might sound like a huge security red flag, but in many cases, multiple signers are essentially one-time use keys corresponding to ephemeral accounts, created as part of the transaction. In such cases, sending their private keys is not a problem. The advantage of this approach is that the recent blockhash can be set right before signing - so avoiding the risk of the transaction becoming stale.


To learn more about making programmatic smart contract calls on Solana with Fordefi, check out our [API Examples public repository](https://github.com/FordefiHQ/api-examples/tree/main/typescript/solana).