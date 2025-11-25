# ===========================
# BOB SIDE
# ===========================

# Terminal colors
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

import socket
import pickle
import rsa_manual
import time

# Server IP and Port (connect to Alice)
HOST = "127.0.0.1"
PORT = 3000

print("Bob connecting to Alice on port:", PORT)

# Generate Bob RSA keys (512-bit primes = 1024-bit key)
print("Generating Bob RSA keys (1024-bit)...")
bob_pub, bob_priv = rsa_manual.generate_keypair(bit_length=512)
print("\nBob keys generated successfully!")
print(f"Bob Public Key (e, n): e={bob_pub[0]}, n bit_length={bob_pub[1].bit_length()}")

# Serialize Bob's public key to send
bob_pub_pickled = pickle.dumps(bob_pub)

while True:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            print(bcolors.HEADER + f"\nConnecting to Alice at {HOST}:{PORT}..." + bcolors.ENDC)
            sock.connect((HOST, PORT))
            print(bcolors.OKBLUE + "Connected to Alice!\n" + bcolors.ENDC)

            # Send Bob's public key to Alice
            print(bcolors.OKCYAN + "Sending Bob's public key to Alice..." + bcolors.ENDC)
            sock.sendall(bob_pub_pickled)

            # Receive encrypted message + Alice's public key from Alice
            alice_data = sock.recv(4096)
            if not alice_data:
                print(bcolors.WARNING + "No data received from Alice, connection closed." + bcolors.ENDC)
                continue

            alice_list = pickle.loads(alice_data)
            alice_cipher = alice_list[0]
            alice_pub = alice_list[1]

            print(bcolors.OKGREEN + "Received encrypted message from Alice:" + bcolors.ENDC)
            print(f"  Ciphertext (integer): {alice_cipher}")
            print(f"  Bit length: {alice_cipher.bit_length()} bits")

            # Decrypt Alice's message with Bob's private key using manual RSA
            print(bcolors.OKCYAN + "Decrypting message with Bob's private key..." + bcolors.ENDC)
            alice_plaintext = rsa_manual.decrypt_to_string(alice_cipher, bob_priv)
            print(bcolors.OKCYAN + "\nDecrypted message from Alice:" + bcolors.ENDC)
            print(bcolors.BOLD + alice_plaintext + bcolors.ENDC)

            # Input message to send to Alice
            bob_msg = input(bcolors.OKGREEN + "\nType a message to send to Alice: " + bcolors.ENDC)

            # Encrypt Bob's message using Alice's public key with manual RSA
            print(bcolors.OKCYAN + "Encrypting message with Alice's public key..." + bcolors.ENDC)
            bob_cipher = rsa_manual.encrypt_string(bob_msg, alice_pub)
            bob_cipher_pickled = pickle.dumps(bob_cipher)

            # Send encrypted message to Alice
            sock.sendall(bob_cipher_pickled)
            print(bcolors.OKBLUE + "Encrypted message sent to Alice!\n" + bcolors.ENDC)

    except Exception as e:
        print(bcolors.FAIL + f"Error: {e}" + bcolors.ENDC)
        print(bcolors.WARNING + "Retrying connection in 5 seconds..." + bcolors.ENDC)
        time.sleep(5)
