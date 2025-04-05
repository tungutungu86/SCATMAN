import socket, threading, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import KEY, STUN_SERVER

def get_public_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"\x00\x01\x00\x00", STUN_SERVER)  # STUN binding request
    data, addr = s.recvfrom(1024)
    return addr  # Returns (public_ip, public_port)

def listen_for_messages(sock):
    aesgcm = AESGCM(KEY)
    while True:
        data, addr = sock.recvfrom(1024)
        nonce, ciphertext = data[:12], data[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        print(f"Other Guy: {plaintext.decode()}")

def send_messages(sock, peer_addr):
    aesgcm = AESGCM(KEY)
    while True:
        message = input("You: ").encode()
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message, None)
        sock.sendto(nonce + ciphertext, peer_addr)

# Step 1: Get public IP/port via STUN
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 5000))  # Bind to any available port
public_ip, public_port = get_public_ip()
print(f"Your public endpoint: {public_ip}:{public_port}")

# Step 2: Share your public endpoint with peer (e.g., via Signal/email)
peer_ip = input("Enter friend's public IP: ")
peer_port = int(input("Enter friend's public port: "))
peer_addr = (peer_ip, peer_port)

# Step 3: Start listening and sending
threading.Thread(target=listen_for_messages, args=(sock,), daemon=True).start()
send_messages(sock, peer_addr)