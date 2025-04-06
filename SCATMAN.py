import socket
import threading
import os
import time
import sys
import signal
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pyDH import DiffieHellman

VERSION = "4"
LEGACY_VERSION = "3"
CHUNK_SIZE = 4096
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

class SecureChat:
    def __init__(self):
        self.dh = DiffieHellman()
        self.sequence = 0
        self.peer_version = "Unknown"
        self.connection_active = True
        self.aesgcm = None
        self.hmac_key = None
        self.aes_key = None
        self.peer_public_key = None
        self.lock = threading.Lock()
        self.MAX_CLOCK_SKEW = 30
        self.legacy_mode = False
        self.file_transfer_lock = threading.Lock() # Lock for file transfer operations

    def derive_keys(self, shared_secret):
        """HKDF-based key derivation with backward compatibility"""
        if self.legacy_mode:
            info = b'belacom-v3-key-derivation'
        else:
            info = f'belacom-v{VERSION}-key-derivation'.encode()
            
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=info
        )
        try:
            keys = hkdf.derive(shared_secret)
            self.aes_key = keys[:32]
            self.hmac_key = keys[32:] if self.legacy_mode else None
            self.aesgcm = AESGCM(self.aes_key)
        except Exception as e:
            raise ValueError(f"Key derivation failed: {str(e)}")

    def perform_version_handshake(self, conn, is_host):
        """Exchange version information with backward compatibility"""
        version_msg = f"BELACOM_VERSION={VERSION}"
        if is_host:
            peer_version_msg = conn.recv(1024).decode().strip()
            self.peer_version = peer_version_msg.split('=')[1]
            conn.send(version_msg.encode())
        else:
            conn.send(version_msg.encode())
            peer_version_msg = conn.recv(1024).decode().strip()
            self.peer_version = peer_version_msg.split('=')[1]
        
        print(f"[INFO] Connected to version {self.peer_version}", file=sys.stderr)
        self.legacy_mode = self.peer_version == LEGACY_VERSION

    def secure_send(self, conn, message, is_file=False, file_data=None):
        with self.lock if not is_file else self.file_transfer_lock:  # Use separate lock for files
            if not self.connection_active:
                raise ConnectionError("Connection closed")
            
            self.sequence += 1
            timestamp = int(time.time())
            nonce = os.urandom(12)
            
            try:
                if is_file:
                    payload = f"FILE|{self.sequence}|{timestamp}|{os.path.basename(message)}|{len(file_data)}".encode() + b'|||' + file_data
                else:
                    payload = f"{self.sequence}|{timestamp}|{message}".encode()

                ciphertext = self.aesgcm.encrypt(nonce, payload, None)
                
                if self.legacy_mode:
                    h = hmac.HMAC(self.hmac_key, hashes.SHA256())
                    h.update(nonce + ciphertext)
                    mac = h.finalize()
                    full_message = nonce + ciphertext + mac
                else:
                    full_message = nonce + ciphertext

                conn.sendall(full_message)
                return True  # Success
            except Exception as e:
                self.sequence -= 1  # Rollback sequence on failure
                raise

    def secure_recv(self, conn):
        try:
            data = conn.recv(4096)
            if not data:
                raise ValueError("Connection closed by peer")

            # Common for both modes
            nonce = data[:12]
            ciphertext = data[12:-32] if self.legacy_mode else data[12:]

            try:
                payload = self.aesgcm.decrypt(nonce, ciphertext, None)
                
                if payload.startswith(b"FILE|"):
                    # Proper file handling
                    header, file_data = payload.split(b"|||", 1)
                    parts = header.decode().split("|")
                    if len(parts) < 5:
                        raise ValueError("Invalid file header")
                    return "FILE", parts[1], parts[2], parts[3], file_data
                else:
                    # Regular message
                    decoded = payload.decode()
                    parts = decoded.split("|", 2)
                    if len(parts) != 3:
                        raise ValueError("Invalid message format")
                    return "MSG", parts[0], parts[1], parts[2]

            except Exception as e:
                raise ValueError(f"Decryption failed: {str(e)}")

        except ConnectionResetError:
            self.connection_active = False
            raise ValueError("Connection reset by peer")

    def send_file(self, conn, filepath):
        try:
            filepath = filepath.strip('"\'')  # Clean path
            if not os.path.exists(filepath):
                raise FileNotFoundError(f"File not found: {filepath}")
                
            filesize = os.path.getsize(filepath)
            if filesize > MAX_FILE_SIZE:
                raise ValueError(f"File exceeds {MAX_FILE_SIZE//(1024*1024)}MB limit")
                
            with open(filepath, 'rb') as f:
                if not self.secure_send(conn, filepath, is_file=True, file_data=f.read()):
                    raise ConnectionError("File transfer failed")
                    
            print(f"[SUCCESS] File sent: {os.path.basename(filepath)}")
            return True
        except Exception as e:
            print(f"[FILE ERROR] {str(e)}")
            return False

    def receive_file(self, filename, file_data):
        """Handle file reception with validation"""
        try:
            if not isinstance(file_data, bytes):
                raise ValueError("Invalid file data format")
                
            print(f"\n[FILE INCOMING] {filename} ({len(file_data)} bytes)")
            if input("Accept file? (y/n): ").lower() != 'y':
                print("[INFO] File transfer cancelled")
                return False
                
            save_dir = "received_files"
            os.makedirs(save_dir, exist_ok=True)
            
            # Secure filename handling
            clean_name = os.path.basename(filename.replace("\\", "").replace("/", ""))
            save_path = os.path.join(save_dir, clean_name)
            
            # Handle duplicates
            counter = 1
            while os.path.exists(save_path):
                name, ext = os.path.splitext(clean_name)
                save_path = os.path.join(save_dir, f"{name}_{counter}{ext}")
                counter += 1
                
            with open(save_path, 'wb') as f:
                f.write(file_data)
                
            print(f"[SUCCESS] Saved to: {save_path}")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to save file: {str(e)}")
            return False

def main():
    signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))
    
    print("\n     _______.  ______     ___   .___________..___  ___.      ___      .__   __. ")
    print("    /       | /      |   /   \  |           ||   \/   |     /   \     |  \ |  | (c) Belacom Technologies Limited")
    print("   |   (----`|  ,----'  /  ^  \ `---|  |----`|  \  /  |    /  ^  \    |   \|  | Powered by paranoia and self torture")
    print("    \   \    |  |      /  /_\  \    |  |     |  |\/|  |   /  /_\  \   |  . `  | (apache 2.0 license)") 
    print(".----)   |   |  `----./  _____  \   |  |     |  |  |  |  /  _____  \  |  |\   | ")
    print("|_______/     \______/__/     \__\  |__|     |__|  |__| /__/     \__\ |__| \__| \n")
    
    secure = SecureChat()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    conn = None

    try:
        print("\n[1] Host (wait for connection)\n[2] Connect to peer")
        while True:
            choice = input("Select mode (1/2): ").strip()
            if choice in ('1', '2'):
                break
            print("[WARNING] That wasn't 1 or 2", file=sys.stderr)

        is_host = choice == '1'
        if is_host:
            port = int(input("Enter port to listen on: "))
            sock.bind(("0.0.0.0", port))
            sock.listen(1)
            print(f"[INFO] Waiting for connection on port {port}...", file=sys.stderr)
            conn, addr = sock.accept()
            print(f"[INFO] Connection from {addr[0]}", file=sys.stderr)
        else:
            peer_ip = input("Enter peer IP: ").strip()
            peer_port = int(input("Enter peer port: "))
            print(f"[INFO] Connecting to {peer_ip}:{peer_port}...", file=sys.stderr)
            sock.connect((peer_ip, peer_port))
            conn = sock
            print("[INFO] Connection established", file=sys.stderr)

        # Key exchange
        if is_host:
            data = conn.recv(4096)
            dh_pub = int(data.decode())
            secure.peer_public_key = dh_pub
            conn.send(str(secure.dh.gen_public_key()).encode())
            shared_key = secure.dh.gen_shared_key(dh_pub)
        else:
            conn.send(str(secure.dh.gen_public_key()).encode())
            data = conn.recv(4096)
            dh_pub = int(data.decode())
            secure.peer_public_key = dh_pub
            shared_key = secure.dh.gen_shared_key(dh_pub)
        
        secure.derive_keys(str(shared_key).encode())
        secure.perform_version_handshake(conn, is_host)
        print("[INFO] Secure channel ready", file=sys.stderr)

        # Start receiver thread
        def receiver():
            while secure.connection_active:
                try:
                    result = secure.secure_recv(conn)
                    
                    if result[0] == "FILE":
                        # Clean file display
                        filename = result[3]
                        filesize = len(result[4])
                        print(f"\n[FILE RECEIVED] {filename} ({filesize} bytes)")
                        secure.receive_file(filename, result[4])
                    else:
                        # Keep the raw tuple display for regular messages
                        print(f"\n{result}")  # Shows ('MSG', seq, timestamp, message)
                        
                except ValueError as e:
                    print(f"\n[WARNING] {str(e)}", file=sys.stderr)
                    secure.connection_active = False
                    break

        threading.Thread(target=receiver, daemon=True).start()

        # Main loop
        while secure.connection_active:
            try:
                message = input()
                if not secure.connection_active:
                    break
                if message.lower() == "/exit":
                    print("[INFO] Closing connection...", file=sys.stderr)
                    break
                elif message.lower().startswith("!sendfile "):
                    filepath = message[10:].strip('"\'')  # Remove quotes if present
                    if not secure.legacy_mode:
                        secure.send_file(conn, filepath)
                    else:
                        print("[ERROR] File transfer not supported in legacy mode", file=sys.stderr)
                else:
                    secure.secure_send(conn, message)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"\n[ERROR] {str(e)}", file=sys.stderr)
                secure.connection_active = False
                break

    except Exception as e:
        print(f"\n[FATAL] {str(e)}", file=sys.stderr)
    finally:
        secure.connection_active = False
        if conn:
            conn.close()
        sock.close()

if __name__ == "__main__":
    main()