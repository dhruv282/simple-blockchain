from random import choice, randrange
from time import time
from datetime import date, timedelta
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

'''
Function to sign given data. Assumes given key is RSA and data is hashed using hash_string()

@param private_key: RSA private key to sign data with
@param data: data to sign
'''
def generate_signature(private_key, data):
    rsa_key = RSA.import_key(private_key.encode())
    hashed_string = hash_string(data)
    return pkcs1_15.new(rsa_key).sign(hashed_string).hex()

'''
Function to verify signature. Assumes given key is RSA and data is hashed using hash_string()

@param public_key: RSA public key to decrypt signature
@param signature: Signature to decrypt
@param data: expected string after signature is decrypted
'''
def verify_signature(public_key, signature, data):
    rsa_key = RSA.import_key(public_key.encode())
    hashed_string = hash_string(data)
    
    try:
        pkcs1_15.new(rsa_key).verify(hashed_string, bytes.fromhex(signature))
        return True
    except:
        return False

'''
Function to hash given string using SHA256

@param string: string to generate a hash for
'''
def hash_string(string):
    return SHA256.new(string.encode('ascii'))


'''
Class to hold transaction info

Attributes:
    - customer_public_key
    - merchant_public_key
    - date
    - amount
    - customer_signature
    - merchant_signature
'''
class transaction:
    def __init__(self, cpk, mpk, date, amount):
        self.customer_public_key = cpk
        self.merchant_public_key = mpk
        self.date = date
        self.amount = amount

    '''
    Function to get transaction info concatenated
    '''
    def get_transaction_concat(self):
        return self.customer_public_key + self.merchant_public_key + self.date + str(self.amount)
    
    '''
    Function to sign transaction info concatenation by customer

    @param customer_private_key: customer's private key
    '''
    def generate_customer_signature(self, customer_private_key):
        string_to_sign = self.get_transaction_concat()
        self.customer_signature = generate_signature(customer_private_key, string_to_sign)

    '''
    Function to verify customer signature
    '''
    def verify_customer_signature(self):
        genesis_key = "0" * 128
        if self.customer_public_key == genesis_key:
            return True
        return verify_signature(self.customer_public_key, self.customer_signature, self.get_transaction_concat())
    
    '''
    Function to sign transaction info concatenation and customer signature by merchant

    @param merchant_private_key: merchant's private key
    '''
    def generate_merchant_signature(self, merchant_private_key):
        string_to_sign = self.get_transaction_concat() + self.customer_signature
        self.merchant_signature = generate_signature(merchant_private_key, string_to_sign)

    '''
    Function to verify merchant signature
    '''
    def verify_merchant_signature(self):
        genesis_key = "0" * 128
        if self.merchant_public_key == genesis_key:
            return True
        return verify_signature(self.merchant_public_key, self.merchant_signature, self.get_transaction_concat() + self.customer_signature)

    '''
    Function to print transaction information
    '''
    def print_transaction(self):
        print("*"*100)
        print("Customer public key:\n" + self.customer_public_key + "\n")
        print("Merchant public key: \n" + self.merchant_public_key + "\n")
        print("Date: " + self.date)
        print("Amount: $" + str(self.amount))
        print("")

'''
Class to hold block information

Attributes:
    - block_trans
    - block_sequence_no
    - previous_block_hash
    - miner_public_key
    - nonce
    - mine_time
    - miner_signature
'''
class block:
    def __init__(self, trans, block_num, prev_hash, miner_public_key):
        self.block_trans = trans
        self.block_sequence_no = block_num
        self.previous_block_hash = prev_hash
        self.miner_public_key = miner_public_key
        self.nonce = 0
        self.mine_time = ""
        self.hash = self.get_block_hash()

    '''
    Function to evaluate block hash using previous block hash, transaction info concatenation, nonce, customer signature, merchant signature and block sequence number
    '''
    def get_block_hash(self):
        string_to_hash = self.previous_block_hash + str(self.nonce) + self.block_trans.get_transaction_concat() + self.block_trans.customer_signature + self.block_trans.merchant_signature + str(self.block_sequence_no)
        return hash_string(string_to_hash).hexdigest()

    '''
    Function to sign merchant signature, block sequence number, and previous block hash by miner

    @param miner_private_key: miner's private key
    '''
    def generate_miner_signature(self, miner_private_key):
        string_to_sign = self.block_trans.merchant_signature + str(self.block_sequence_no) + self.previous_block_hash
        self.miner_signature = generate_signature(miner_private_key, string_to_sign)

    '''
    Function to mine block

    @param difficulty: amount of leading zeros required in blocked hash
    '''
    def mine_block(self, difficulty):
        start_time = time()
        while not self.hash.startswith('0'*difficulty):
            self.nonce += 1
            self.hash = self.get_block_hash()
        self.mine_time = time() - start_time

    '''
    Function to print block information
    '''
    def print_block_info(self):
        print("*"*100)
        print("Hash: " + self.hash)
        print("Block #: " + str(self.block_sequence_no))
        print("# of nonces attempted: " + str(self.nonce))
        print("Time taken to mine block: " + str(round(self.mine_time, 4)) + "s")
        print("")

'''
Class to store blockchain information

Attributes:
    - chain
'''
class blockchain:
    def __init__(self, difficulty=0):
        self.chain = []
        self.difficulty = difficulty

    '''
    Function to get latest block in the chain
    '''
    def get_latest_block(self):
        return self.chain[-1]

    '''
    Function to get a block in the chain using given block sequence number

    @param block_num: block sequence number for the requested block
    '''
    def get_block(self, block_num):
        if block_num >= 0 and block_num < len(self.chain):
            return self.chain[block_num]
        else:
            return False

    '''
    Function to add a block to the chain

    @param customer_public_key: customer's public key
    @param merchant_public_key: merchant's public key
    @param date: date of transaction
    @param amount: amount involved in the transaction
    @param customer_private_key: customer's private key to sign transaction
    @param merchant_private_key: merchant's private key to sign the transaction
    @param miner_private_key: miner's private key to sign the block
    '''
    def add_block(self, customer_public_key, merchant_public_key, miner_public_key, date, amount, customer_private_key, merchant_private_key, miner_private_key):
        prev_hash = self.get_latest_block().get_block_hash()

        new_transaction = transaction(customer_public_key, merchant_public_key, date, amount)
        new_transaction.generate_customer_signature(customer_private_key)
        new_transaction.generate_merchant_signature(merchant_private_key)

        new_block = block(new_transaction, len(self.chain), prev_hash, miner_public_key)
        new_block.mine_block(self.difficulty)
        new_block.generate_miner_signature(miner_private_key)

        self.chain.append(new_block)

    '''
    Function to generate the genesis block in the chain. The chain must be empty
    '''
    def create_genesis_block(self):
        if len(self.chain) == 0:
            genesis_key = "0" * 128
            genesis_date = "0" * 10
            genesis_amount = 0

            genesis_transaction = transaction(genesis_key, genesis_key, genesis_date, genesis_amount)
            genesis_transaction.customer_signature = genesis_key
            genesis_transaction.merchant_signature = genesis_key
            
            genesis_prev_hash = "0" * 32
            genesis_block = block(genesis_transaction, 0, genesis_prev_hash, genesis_key)
            self.chain.append(genesis_block)
        else:
            print("ERROR: chain already initialized")
            return False

    '''
    Function to validate trnasactions and blocks in the chain
    '''
    def check_chain_validity(self):
        if len(self.chain) > 0:
            for i in range(1, len(self.chain)):
                cur_block = self.chain[i]
                prev_block = self.chain[i-1]

                if (not cur_block.block_trans.verify_customer_signature()) or (not cur_block.block_trans.verify_merchant_signature()):
                    return False
                
                if cur_block.previous_block_hash != prev_block.get_block_hash():
                    return False
        
        return True

    '''
    Function to get a list of the given user's transactions
    '''
    def get_user_transactions(self, public_key):
        trans = []
        for block in self.chain:
            if block.block_trans.customer_public_key == public_key:
                trans.append(block.block_trans)
            
            if block.block_trans.merchant_public_key == public_key:
                trans.append(block.block_trans)
        return trans


'''
Function create simulated users

@param num_customers: number of customers to generate
@param num_merchants: number of merchants to generate
@param num_miners: number of miners to generate
'''
def create_users(num_customers=5, num_merchants=2, num_miners=1):
    customers = [RSA.generate(1024) for _ in range(num_customers)]
    merchants = [RSA.generate(1024) for _ in range(num_merchants)]
    miners = [RSA.generate(1024) for _ in range(num_miners)]

    return customers, merchants, miners

'''
Function to generate a random date that occurs atleast on the seed date and atmost 5 days after the seed date

@param seed_date: date to base the randomization on
'''
def generate_random_date(seed_date):
    rand_days = randrange(5)
    return seed_date + timedelta(days=rand_days)

def main():
    # prompt the user for mining difficulty
    diff = -1
    while diff < 0:
        diff = int(input("Please enter the diffculty to mine blocks (# of leading 0s in block hash): "))

    # initialize blockchain
    my_crypto = blockchain(difficulty=diff)
    my_crypto.create_genesis_block()
    #my_crypto.chain[-1].block_trans.print_transaction()


    '''
    TRANSACTION SIMULATION
    '''
    # prompt the user for number of transactions to geenrate for the simulation
    num_of_transactions_to_simulate = -1
    while num_of_transactions_to_simulate < 0:
        num_of_transactions_to_simulate = int(input("Please enter the number of transactions you would like to simulate: "))
    print("")

    # initialize variables
    seed_date = date.today()
    customers, merchants, miners = create_users()

    for _ in range(num_of_transactions_to_simulate):
        # select random values
        random_customer = choice(customers)
        random_merchant = choice(merchants)
        random_amount = randrange(1,500)

        # update seed to avoid misaligned dates
        seed_date = generate_random_date(seed_date)

        # get date string (mmddyyyy)
        random_date = seed_date.strftime('%m/%d/%Y')

        random_miner = choice(miners)

        # simulate transaction
        my_crypto.add_block(random_customer.publickey().export_key().decode(),
                            random_merchant.publickey().export_key().decode(),
                            random_miner.publickey().export_key().decode(),
                            random_date, random_amount,
                            random_customer.export_key().decode(),
                            random_merchant.export_key().decode(),
                            random_miner.export_key().decode())
        
        # print transaction
        #my_crypto.chain[-1].block_trans.print_transaction()

        # print block info
        my_crypto.chain[-1].print_block_info()


    '''
    CHAIN SEARCHING
    '''
    print("")
    # prompt the user to select a customer to acquire transactions of
    which_customer = -1

    # validate input
    while which_customer < 0 or which_customer >= len(customers):
        which_customer = int(input("Which customer's transactions would you like to view? (0-" + str(len(customers) - 1) + ") "))
    
    # acquire and print transaction info
    customer_trans = my_crypto.get_user_transactions(customers[which_customer].publickey().export_key().decode())
    if len(customer_trans) > 0:
        for trans in customer_trans:
            trans.print_transaction()
    else:
        print("Customer " + str(which_customer) + " does not have any transactions\n")

    # prompt the user to select a merchant to acquire transactions of
    which_merchant = -1

    # validate input
    while which_merchant < 0 or which_merchant >= len(merchants):
        which_merchant = int(input("Which merchant's transactions would you like to view? (0-" + str(len(merchants) - 1) + ") "))
    
    # acquire and print transaction info
    merchant_trans = my_crypto.get_user_transactions(merchants[which_merchant].publickey().export_key().decode())
    if len(merchant_trans) > 0:
        for trans in merchant_trans:
            trans.print_transaction()
    else:
        print("Merchant " + str(which_merchant) + " does not have any transactions\n")


    '''
    CHAIN TAMPERING
    '''
    # prompt user to tamper with chain
    print("")
    ask_to_tamper = input("Would you like to tamper with the chain? (y/N) ")
    
    if ask_to_tamper == "y" or ask_to_tamper == "Y":
        # prompt user to enter block number to tamper with
        which_block = -1
        
        # validate user input
        while which_block < 0 or which_block >= len(my_crypto.chain):
            which_block = int(input("Which block would you like to change? (0-" + str(len(my_crypto.chain)-1) + ") "))
        
        # prompt the user for the amount to add
        amount = int(input("Amount to add on to block " + str(which_block) + ": $"))

        # tamper with chain
        my_crypto.chain[which_block].block_trans.amount += amount
    print("")

    # validate chain integrity
    if my_crypto.check_chain_validity():
        print("Chain is valid")
    else:
        print("WARNING: Chain has been tampered with")
    


if __name__ == "__main__":
    main()