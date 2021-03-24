# Simple Blockchain

This program consists of a simple blockchain structure implemented in [Python](https://www.python.org/). The program uses RSA encryption and SHA-256 hashing schemes from [PyCryptodome](https://github.com/Legrandin/pycryptodome/).


## Implementation

The program consists of a transaction that holds the following information:

* Customer public key
* Merchant public key
* Date of transaction
* Amount involved in the transaction
* Customer signature (created by calling `generate_customer_signature()`)
* Merchant signature (created by calling `generate_merchant_signature()`)

A block class is implemented to hold transaction information along with the following information:

* Block sequence number
* Previous block hash
* Miner's signature

**Note:** Each block consists of only one transaction. Real World implementations generally have many transactions in one block. 

Finally, the program consists of a `blockchain` to manage a chain of blocks. This class provides functionality to do the following:

* Create and add a genesis block
* Add blocks to the chain and sign information immediately
* Get latest block in the chain
* Get a specific block in the chain
* Verify chain validity
* Get transactions made by a given user

Program execution begins by prompt the user to enter the number of transactions to simulate. The program will create simulated customers, merchants, and miners and generate random transactions based on user input. The user is able to view a customer or merchant's transaction history. The user can also tamper with the chain by incrementing the transaction amount of a selected block. This is to demonstrate that the chain validation is able to detect such issues since tampering with the transaction info will produce completely different hashes and lead to the signatures not being verified.

## Usage
This documentation assumes that you have [Python3](https://www.python.org/downloads/) setup along with the [PyCryptodome](https://github.com/Legrandin/pycryptodome/) package. Run the following command to execute the program:

```shell
$ python3 blockchain.py
```
