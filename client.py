import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import json

class SecureChatClient:
    """
    Class to manage the secure chat client.
    """
    def __init__(self, host='127.0.0.1', port=5555):
        """
        Initializes the client socket and connects to the server.
        It then receives the shared key from the server and starts a thread for receiving messages.
        """
        self.host = host
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))
        self.shared_key = self.receive_key()
        print("Connected to server. Encryption key received.")
        threading.Thread(target=self.receive_messages, daemon=True).start()
        self.start()

    def receive_key(self):
        """
        Receives the shared encryption key from the server.
        """
        key_data = self.client.recv(1024)
        return bytes.fromhex(json.loads(key_data.decode())['key'])

    def start(self):
        """
        Sends user input messages to the server after encrypting them.
        """
        while True:
            message = input("You: ")
            encrypted_msg = self.encrypt_message(message)
            try:
                self.client.send(encrypted_msg)
            except Exception as e:
                print(f"Error sending message: {e}")
                break

    def receive_messages(self):
        """
        Receives encrypted messages from the server, decrypts them, and prints them to the console.
        """
        while True:
            try:
                encrypted_data = self.client.recv(1024)
                if not encrypted_data:
                    print("Disconnected from server.")
                    break
                decrypted_msg = self.decrypt_message(encrypted_data)
                print(f"\n{decrypted_msg}\nYou: ", end="")
            except Exception as e:
                print(f"Error receiving or decrypting message: {e}")
                break

    def encrypt_message(self, message):
        """
        Encrypts the message using AES-256 in CBC mode with PKCS7 padding.

        Args:
            message (str): The message to encrypt.

        Returns:
            bytes: The encrypted data (IV + ciphertext).
        """
        message_bytes = message.encode('utf-8')
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message_bytes) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.shared_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_message

    def decrypt_message(self, encrypted_data):
        """
        Decrypts the received data using AES-256 in CBC mode with PKCS7 padding.

        Args:
            encrypted_data (bytes): The data to decrypt.

        Returns:
            str: The decrypted message.
        """
        iv = encrypted_data[:16]  # Extract the IV
        encrypted_message = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(self.shared_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_message) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        return unpadded_data.decode('utf-8')

if __name__ == "__main__":
    SecureChatClient()
