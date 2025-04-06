import socket
import threading
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

class SecureChatServer:
    """
    Class to manage the secure chat server.
    """
    def __init__(self, host='127.0.0.1', port=5555):
        """
        Initializes the server socket, binds it to a host and port, and starts listening for connections.
        It also generates a shared key for encryption and starts a thread for server chat.
        """
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"Server started on {self.host}:{self.port}")
        self.clients = {}  # Use a dictionary to store clients and their addresses
        self.shared_key = os.urandom(32)  # Use 256-bit key for AES-256
        print("Generated encryption key:", self.shared_key.hex())
        threading.Thread(target=self.server_chat, daemon=True).start()  # Run server chat in a daemon thread
        self.start()

    def start(self):
        """
        Accepts incoming client connections in a loop, stores the client socket and address,
        sends the shared key to the client, and starts a new thread to handle each client.
        """
        while True:
            client_socket, addr = self.server.accept()
            print(f"Connection from {addr}")
            self.clients[addr] = client_socket  # Store client socket with address as key
            self.send_key(client_socket) #send key after client connects
            threading.Thread(target=self.handle_client, args=(addr,)).start()

    def send_key(self, client_socket):
        """
        Sends the shared encryption key to the client.

        Args:
            client_socket (socket.socket): The socket connected to the client.
        """
        try:
            client_socket.send(json.dumps({'key': self.shared_key.hex()}).encode())
        except Exception as e:
            print(f"Error sending key to client: {e}")

    def handle_client(self, addr):
        """
        Handles communication with a connected client.  Receives encrypted data,
        decrypts it, and broadcasts the message to other clients.  Includes a disconnect
        message.

        Args:
            addr (tuple): The address of the connected client (host, port).
        """
        client_socket = self.clients[addr]
        try:
            while True:
                encrypted_data = client_socket.recv(1024)
                if not encrypted_data:
                    break
                try:
                    decrypted_msg = self.decrypt_message(encrypted_data)
                    print(f"Client {addr}: {decrypted_msg}")
                    self.broadcast(f"Client {addr}: {decrypted_msg}", addr)
                except Exception as e:
                    print(f"Error decrypting or broadcasting message from {addr}: {e}")
                    break  # Exit loop on decryption error
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            print(f"Client {addr} disconnected.")
            client_socket.close()
            del self.clients[addr]  # Remove client from the dictionary
            self.broadcast(f"Client {addr} disconnected.", addr) #inform other clients

    def server_chat(self):
        """
        Handles server-side chat input and broadcasts messages to all connected clients.
        """
        while True:
            message = input("Server: ")
            self.broadcast(f"Server: {message}", ('Server',))  # Use a tuple for server's "address"

    def decrypt_message(self, encrypted_data):
        """
        Decrypts the received data using AES-256 in CBC mode with PKCS7 padding.

        Args:
            encrypted_data (bytes): The data to decrypt.

        Returns:
            str: The decrypted message.
        """
        iv = encrypted_data[:16]  # Extract the IV
        encrypted_message = encrypted_data[16:] #get the encrypted message
        cipher = Cipher(algorithms.AES(self.shared_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_message) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        return unpadded_data.decode('utf-8')

    def broadcast(self, message, sender_addr=None):
        """
        Broadcasts a message to all connected clients except the sender.

        Args:
            message (str): The message to broadcast.
            sender_addr (tuple, optional): The address of the sender. Defaults to None.
        """
        encrypted_msg = self.encrypt_message(message)
        for addr, client_socket in self.clients.items():
            if addr != sender_addr:
                try:
                    client_socket.send(encrypted_msg)
                except Exception as e:
                    print(f"Error sending message to {addr}: {e}")
                    # Consider removing the client if sending fails
                    print(f"Removing client {addr} due to error.")
                    client_socket.close()
                    del self.clients[addr]

    def encrypt_message(self, message):
        """
        Encrypts the message using AES-256 in CBC mode with PKCS7 padding.

        Args:
            message (str): The message to encrypt.

        Returns:
            bytes: The encrypted data (IV + ciphertext).
        """
        message_bytes = message.encode('utf-8')
        iv = os.urandom(16)  # Generate a unique IV for each message
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message_bytes) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.shared_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_message

if __name__ == "__main__":
    SecureChatServer()
