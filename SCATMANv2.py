import socket
import threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyDH import DiffieHellman
import os
import sys

class SecureChat:
    def __init__(self):
        self.dh = DiffieHellman()
        self.peer_pubkey = None
        self.shared_key = None
        self.aesgcm = None
        self.running = True

    def generate_shared_key(self):
        """Generate shared key using peer's public key"""
        try:
            self.shared_key = str(self.dh.gen_shared_key(self.peer_pubkey))[:32].encode()
            self.aesgcm = AESGCM(self.shared_key)
            print("[INFO] Encryption initialized")
        except Exception as e:
            print(f"[WARNING] Key setup failed: {str(e)}")
            raise

def receive_messages(conn, secure):
    while secure.running:
        try:
            data = conn.recv(4096)
            if not data:
                print("\n[INFO] Peer disconnected")
                break

            if not secure.shared_key:
                secure.peer_pubkey = int(data.decode())
                conn.send(str(secure.dh.gen_public_key()).encode())
                secure.generate_shared_key()
            else:
                nonce, ciphertext = data[:12], data[12:]
                message = secure.aesgcm.decrypt(nonce, ciphertext, None).decode()
                print(f"\n{message}")
        except ConnectionResetError:
            print("\n[INFO] Connection closed by peer")
            break
        except Exception as e:
            if secure.running:
                print(f"\n[WARNING] Decryption error: {str(e)}")
            break

def main():
    print("\n=== Belacom Secure Terminal ===")
    secure = SecureChat()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    conn = None  # Initialize connection object

    try:
        # Connection setup
        print("\n[1] Host (wait for connection)\n[2] Connect to peer")
        while True:
            choice = input("Select mode (1/2): ").strip()
            if choice in ('1', '2'):
                break
            print("[WARNING] Invalid selection")

        if choice == '1':
            port = int(input("Enter port to listen on: "))
            sock.bind(("0.0.0.0", port))
            sock.listen(1)
            print(f"[INFO] Waiting for connection on port {port}...")
            conn, addr = sock.accept()
            print(f"[INFO] Connected to {addr[0]}:{addr[1]}")
            
            # Key exchange
            secure.peer_pubkey = int(conn.recv(4096).decode())
            conn.send(str(secure.dh.gen_public_key()).encode())
        else:
            peer_ip = input("Enter peer IP: ").strip()
            peer_port = int(input("Enter peer port: "))
            print(f"[INFO] Connecting to {peer_ip}:{peer_port}...")
            sock.connect((peer_ip, peer_port))
            conn = sock
            print("[INFO] Connection established")
            
            # Key exchange
            conn.send(str(secure.dh.gen_public_key()).encode())
            secure.peer_pubkey = int(conn.recv(4096).decode())

        secure.generate_shared_key()
        print("\n[INFO] Secure channel ready - Begin messaging (Ctrl+C to exit)\n")

        # Start receiver thread
        receiver = threading.Thread(target=receive_messages, args=(conn, secure))
        receiver.start()

        # Message input loop
        while secure.running:
            try:
                message = input()
                if message.lower() == "/exit":
                    break
                    
                nonce = os.urandom(12)
                ciphertext = secure.aesgcm.encrypt(nonce, message.encode(), None)
                conn.send(nonce + ciphertext)
            except KeyboardInterrupt:
                print("\n[INFO] Closing connection...")
                break
            except Exception as e:
                print(f"\n[WARNING] Send error: {str(e)}")
                break

    except Exception as e:
        print(f"\n[WARNING] System error: {str(e)}")
    finally:
        secure.running = False
        if conn:
            conn.close()
        sock.close()
        print("[INFO] Session terminated")
        sys.exit(0)

if __name__ == "__main__":
    main()