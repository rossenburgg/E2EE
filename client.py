import socket
import threading
import json
import time
import logging
from crypto_utils import *

# Set up logging to see what's happening
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('E2EE_Client')


class Client:
    def __init__(self, host='127.0.0.1', port=5000):
        # Set up the basic information for connecting to the server
        self.host = host
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Ask for the user's name
        self.username = input("Enter your username: ")

        # Create special keys for secure communication
        logger.info(f"Generating RSA and ECC key pairs for {self.username}")
        self.rsa_private_key, self.rsa_public_key = generate_rsa_key_pair()
        self.ecc_private_key, self.ecc_public_key = generate_ecc_key_pair()

        # Prepare storage for secret keys with other users
        self.session_keys = {}
        self.key_exchange_in_progress = set()

    def connect(self):
        # Try to connect to the server
        for port in range(self.port, 65535):
            try:
                self.client.connect((self.host, port))
                self.port = port
                break
            except ConnectionRefusedError:
                continue
        else:
            logger.error("Could not connect to the server.")
            return

        # Send the username to the server
        self.client.send(self.username.encode('utf-8'))
        logger.info(f"Connected to server at {self.host}:{self.port}")

        # Start listening for messages in a separate thread
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()

        # Start sending messages
        self.send_messages()

    def receive_messages(self):
        while True:
            try:
                # Wait for a message from the server
                message = self.client.recv(1024).decode('utf-8')
                data = json.loads(message)
                logger.info(f"Received message: {data}")

                # Handle different types of messages
                if 'ecc_public_key' in data:
                    self.handle_key_exchange(data)
                elif 'encrypted_message' in data:
                    self.handle_encrypted_message(data)
                elif 'error' in data:
                    logger.error(f"Error: {data['error']}")
            except Exception as e:
                logger.error(f"Error: {e}")
                break

    def send_messages(self):
        while True:
            # Ask who to send a message to and what the message is
            recipient = input("Enter recipient's username: ")
            message = input("Enter your message: ")

            # If we haven't talked to this person before, set up a secure connection
            if recipient not in self.session_keys:
                if recipient not in self.key_exchange_in_progress:
                    self.initiate_key_exchange(recipient)
                    self.key_exchange_in_progress.add(recipient)

                logger.info("Key exchange in progress. Please wait...")
                start_time = time.time()
                while recipient not in self.session_keys:
                    time.sleep(0.1)
                    if time.time() - start_time > 10:  # Timeout after 10 seconds
                        logger.error("Key exchange timed out")
                        break
                self.key_exchange_in_progress.discard(recipient)

            if recipient in self.session_keys:
                # Encrypt the message
                logger.info(f"Encrypting message for {recipient}")
                encryption_key, hmac_key, next_key = self.session_keys[recipient]
                encrypted_message = encrypt_message(message, encryption_key, hmac_key)

                # Prepare the message to send
                data = {
                    "sender": self.username,
                    "recipient": recipient,
                    "encrypted_message": encrypted_message
                }

                # Send the encrypted message
                self.client.send(json.dumps(data).encode('utf-8'))
                logger.info(f"Sent encrypted message to {recipient}")

                # Update the secret keys for next time
                self.session_keys[recipient] = ratchet_keys(next_key)
            else:
                logger.error(f"Failed to establish secure connection with {recipient}")

    def initiate_key_exchange(self, recipient):
        # Start the process of creating a secure connection with someone
        logger.info(f"Initiating key exchange with {recipient}")
        data = {
            "sender": self.username,
            "recipient": recipient,
            "ecc_public_key": self.ecc_public_key
        }
        self.client.send(json.dumps(data).encode('utf-8'))

    def handle_key_exchange(self, data):
        # Complete the process of creating a secure connection
        sender = data['sender']
        logger.info(f"Handling key exchange request from {sender}")
        peer_public_key = data['ecc_public_key']
        shared_secret = perform_diffie_hellman(self.ecc_private_key, peer_public_key)
        encryption_key, hmac_key, next_key = derive_keys(shared_secret)
        self.session_keys[sender] = (encryption_key, hmac_key, next_key)
        logger.info(f"Established session keys with {sender}")

        # Send our public key back if we didn't initiate the exchange
        if sender not in self.key_exchange_in_progress:
            response = {
                "sender": self.username,
                "recipient": sender,
                "ecc_public_key": self.ecc_public_key
            }
            self.client.send(json.dumps(response).encode('utf-8'))

    def handle_encrypted_message(self, data):
        # Deal with an incoming secret message
        sender = data['sender']
        encrypted_message = data['encrypted_message']
        logger.info(f"Received encrypted message from {sender}")
        if sender in self.session_keys:
            encryption_key, hmac_key, next_key = self.session_keys[sender]
            try:
                # Try to unlock the secret message
                decrypted_message = decrypt_message(encrypted_message, encryption_key, hmac_key)
                logger.info(f"Decrypted message from {sender}")
                print(f"{sender}: {decrypted_message}")

                # Update the secret keys for next time
                self.session_keys[sender] = ratchet_keys(next_key)
            except ValueError as e:
                logger.error(f"Failed to decrypt message from {sender}: {e}")
        else:
            logger.error(f"No session keys for {sender}")


if __name__ == "__main__":
    client = Client()
    client.connect()