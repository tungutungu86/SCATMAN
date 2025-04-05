import socket
import threading
import os
import time
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pyDH import DiffieHellman

class SecureChatV3:
    def __init__(self):
        self.dh = DiffieHellman()
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.peer_public_key = None
        self.sequence = 0
        self.last_timestamp = 0
        self.MAX_CLOCK_SKEW = 30  # seconds

    def derive_keys(self, shared_secret):
        """HKDF-based key derivation with forward secrecy"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'belacom-v3-key-derivation'
        )
        keys = hkdf.derive(shared_secret)
        self.aes_key = keys[:32]
        self.hmac_key = keys[32:]
        self.aesgcm = AESGCM(self.aes_key)

    def secure_send(self, conn, message):
        """Anti-replay protected sending"""
        self.sequence += 1
        timestamp = int(time.time())
        nonce = os.urandom(12)
        
        payload = f"{self.sequence}|{timestamp}|{message}".encode()
        ciphertext = self.aesgcm.encrypt(nonce, payload, None)
        
        # HMAC for integrity
        h = hmac.HMAC(self.hmac_key, hashes.SHA256())
        h.update(nonce + ciphertext)
        mac = h.finalize()
        
        conn.sendall(nonce + ciphertext + mac)

    def secure_recv(self, conn):
        """Secure message reception with replay protection"""
        data = conn.recv(4096)
        if len(data) < 44:  # 12 nonce + 16 min ciphertext + 16 MAC
            raise ValueError("Invalid message length")
            
        nonce = data[:12]
        ciphertext = data[12:-32]
        received_mac = data[-32:]
        
        # Verify HMAC
        h = hmac.HMAC(self.hmac_key, hashes.SHA256())
        h.update(nonce + ciphertext)
        try:
            h.verify(received_mac)
        except:
            raise ValueError("HMAC verification failed")
        
        # Decrypt
        payload = self.aesgcm.decrypt(nonce, ciphertext, None).decode()
        seq, timestamp, message = payload.split("|", 2)
        
        # Anti-replay checks
        current_time = int(time.time())
        if abs(current_time - int(timestamp)) > self.MAX_CLOCK_SKEW:
            raise ValueError("Message timestamp outside allowed window")
        
        if int(seq) <= self.sequence:
            raise ValueError("Potential replay attack detected")
            
        self.sequence = int(seq)
        return message

def main():
    print("\n     _______.  ______     ___   .___________..___  ___.      ___      .__   __. ")
    print("    /       | /      |   /   \  |           ||   \/   |     /   \     |  \ |  | (c) Belacom Technologies Limited")
    print("   |   (----`|  ,----'  /  ^  \ `---|  |----`|  \  /  |    /  ^  \    |   \|  | Powered by paranoia and self torture")
    print("    \   \    |  |      /  /_\  \    |  |     |  |\/|  |   /  /_\  \   |  . `  | (apache 2.0 license)") 
    print(".----)   |   |  `----./  _____  \   |  |     |  |  |  |  /  _____  \  |  |\   | ")
    print("|_______/     \______/__/     \__\  |__|     |__|  |__| /__/     \__\ |__| \__| \n")
    
    secure = SecureChatV3()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    conn = None

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
            print(f"[INFO] Connected to {addr[0]}")
            
            # Key exchange
            data = conn.recv(4096)
            dh_pub = int(data.decode())
            secure.peer_public_key = dh_pub
            conn.send(str(secure.dh.gen_public_key()).encode())
            secure.derive_keys(str(secure.dh.gen_shared_key(dh_pub)).encode())
        else:
            peer_ip = input("Enter peer IP: ").strip()
            peer_port = int(input("Enter peer port: "))
            print(f"[INFO] Connecting to {peer_ip}:{peer_port}...")
            sock.connect((peer_ip, peer_port))
            conn = sock
            print("[INFO] Connection established")
            
            # Key exchange
            conn.send(str(secure.dh.gen_public_key()).encode())
            dh_pub = int(conn.recv(4096).decode())
            secure.peer_public_key = dh_pub
            secure.derive_keys(str(secure.dh.gen_shared_key(dh_pub)).encode())

        print("[INFO] Secure channel established")

        # Start receiver thread
        def receiver():
            while True:
                try:
                    msg = secure.secure_recv(conn)
                    print(f"\n{msg}")
                except ValueError as e:
                    print(f"\n[SECURITY ALERT] {str(e)}")
                    os._exit(1)

        threading.Thread(target=receiver, daemon=True).start()

        # Main loop
        while True:
            try:
                message = input()
                if message.lower() == "/exit":
                    break
                secure.secure_send(conn, message)
            except KeyboardInterrupt:
                print("\n[INFO] Graceful shutdown initiated")
                break
            except Exception as e:
                print(f"\n[ERROR] {str(e)}")
                break

    except Exception as e:
        print(f"\n[CRITICAL] {str(e)}")
    finally:
        if conn:
            conn.close()
        sock.close()
        print("[INFO] Connection terminated")

if __name__ == "__main__":
    main()