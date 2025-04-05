import socket
import threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import KEY, STUN_SERVER
import os

def get_public_ip():
    """Get public IP/port via STUN"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"\x00\x01\x00\x00", STUN_SERVER)  # STUN binding request
    data, addr = s.recvfrom(1024)
    return addr  # (public_ip, public_port)

def listen_for_messages(sock):
    """Decrypt and print incoming messages"""
    aesgcm = AESGCM(KEY)
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            nonce, ciphertext = data[:12], data[12:]
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            print(f"\nFriend: {plaintext.decode()}")
        except:
            print("Decryption failed (wrong key?)")

def send_messages(sock, peer_addr):
    """Encrypt and send user input"""
    aesgcm = AESGCM(KEY)
    while True:
        message = input("You: ").encode()
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message, None)
        sock.sendto(nonce + ciphertext, peer_addr)

# --- Main Execution ---
if __name__ == "__main__":
    # Set up UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 5000))  # Bind to random local port

    # Get public endpoint via STUN
    public_ip, public_port = get_public_ip()
    print(f"Your public endpoint: {public_ip}:{public_port}")

    # Share this with Peer A (e.g., via Signal/email)
    peer_ip = input("Enter Peer A's public IP: ")
    peer_port = int(input("Enter Peer A's public port: "))
    peer_addr = (peer_ip, peer_port)

    # Start threads for async send/receive
    threading.Thread(
        target=listen_for_messages, 
        args=(sock,), 
        daemon=True
    ).start()
    
    send_messages(sock, peer_addr)