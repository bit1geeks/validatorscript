import hashlib
import json
import time
import base64
import ecdsa
import click

class Transaction:
    def __init__(self, sender, recipient, amount):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.timestamp = time.time()

    def to_dict(self):
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'timestamp': self.timestamp,
        }

    def sign_transaction(self, private_key):
        transaction_dict = self.to_dict()
        transaction_json = json.dumps(transaction_dict, sort_keys=True).encode()
        signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
        signature = signing_key.sign(transaction_json)
        return base64.b64encode(signature).decode()

    @staticmethod
    def verify_signature(transaction_dict, signature, public_key):
        transaction_json = json.dumps(transaction_dict, sort_keys=True).encode()
        verifying_key = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
        try:
            return verifying_key.verify(base64.b64decode(signature), transaction_json)
        except ecdsa.BadSignatureError:
            return False

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.hash = self.hash_block()

    def hash_block(self):
        block_string = json.dumps({
            'index': self.index,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

class BlockchainValidator:
    def __init__(self):
        self.transactions = []
        self.blocks = []
        self.create_block(previous_hash='0')  # Create genesis block

    def create_block(self, previous_hash):
        block = Block(index=len(self.blocks) + 1,
                      transactions=self.transactions,
                      timestamp=time.time(),
                      previous_hash=previous_hash)
        self.blocks.append(block)
        self.transactions = []  # Reset transaction list after mining
        return block

    def add_transaction(self, transaction, signature):
        if not self.verify_transaction(transaction, signature):
            raise ValueError("Invalid transaction signature")
        self.transactions.append(transaction)
        print(f"Transaction added: {transaction.to_dict()}")

    def verify_transaction(self, transaction, signature):
        return Transaction.verify_signature(transaction.to_dict(), signature, transaction.sender)

@click.command()
@click.option('--private_key', prompt='Your private key', help='Your private key for signing transactions.')
@click.option('--public_key', prompt='Your public key', help='Your public key for verifying transactions.')
def cli(private_key, public_key):
    validator = BlockchainValidator()

    while True:
        print("\n1. Add Transaction")
        print("2. Mine Block")
        print("3. View Blockchain")
        print("4. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            recipient = input("Recipient: ")
            amount = float(input("Amount: "))
            transaction = Transaction(sender=public_key, recipient=recipient, amount=amount)
            signature = transaction.sign_transaction(private_key)
            try:
                validator.add_transaction(transaction, signature)
            except ValueError as e:
                print(e)

        elif choice == '2':
            previous_hash = validator.blocks[-1].hash if validator.blocks else '0'
            block = validator.create_block(previous_hash)
            print(f"Block mined: {block.index} with hash: {block.hash}")

        elif choice == '3':
            for block in validator.blocks:
                print(f"Block {block.index}: {block.hash}")
                for tx in block.transactions:
                    print(f"  Transaction: {tx.to_dict()}")
            if not validator.blocks:
                print("No blocks mined yet.")

        elif choice == '4':
            break

        else:
            print("Invalid option. Please try again.")

if __name__ == '__main__':
    cli()
