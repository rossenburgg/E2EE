import socket
import threading
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('E2EE_Server')

class Server:
    def __init__(self, host='127.0.0.1', port=5000):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}

    def start(self):
        for port in range(self.port, 65535):
            try:
                self.server.bind((self.host, port))
                self.port = port
                break
            except OSError:
                continue
        else:
            logger.error("Could not find an available port.")
            return

        self.server.listen()
        logger.info(f"Server is listening on {self.host}:{self.port}")
        while True:
            try:
                client, address = self.server.accept()
                thread = threading.Thread(target=self.handle_client, args=(client, address))
                thread.start()
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")

    def handle_client(self, client, address):
        username = client.recv(1024).decode('utf-8')
        self.clients[username] = client
        logger.info(f"{username} connected from {address}")

        while True:
            try:
                message = client.recv(1024).decode('utf-8')
                if not message:
                    break
                data = json.loads(message)
                logger.info(f"Received message: {data}")
                if data['recipient'] in self.clients:
                    self.clients[data['recipient']].send(json.dumps(data).encode('utf-8'))
                    logger.info(f"Forwarded message from {data['sender']} to {data['recipient']}")
                else:
                    client.send(json.dumps({"error": "Recipient not found"}).encode('utf-8'))
                    logger.warning(f"Recipient {data['recipient']} not found")
            except Exception as e:
                logger.error(f"Error handling client {username}: {e}")
                break

        logger.info(f"{username} disconnected")
        del self.clients[username]
        client.close()

if __name__ == "__main__":
    server = Server()
    server.start()