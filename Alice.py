# ===========================
# ALICE SIDE
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

# Imports
import rsa
import socket
import pickle

# Host and Port
HOST = "0.0.0.0"    # Listen on all interfaces
PORT = 3000

print("Alice running on port:", PORT)

# Create socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)

# Generate RSA key pair
print("Generating Alice RSA keys...")
alice_pub, alice_priv = rsa.newkeys(1024)
print("Keys generated successfully!")

while True:
    print(bcolors.HEADER + "\nWaiting for Bob to connect..." + bcolors.ENDC)
    clientSocket, address = server.accept()
    print(bcolors.OKBLUE + f"Connected to Bob at {address}" + bcolors.ENDC)

    try:
        while True:
            # Receive Bob public key
            bobPubPick = clientSocket.recv(4096)

            if not bobPubPick:
                print(bcolors.WARNING + "Connection closed by Bob" + bcolors.ENDC)
                break

            bob_pub = pickle.loads(bobPubPick)

            print(bcolors.OKCYAN + "\nAlice Public Key (unchanged):" + bcolors.ENDC)
            print(alice_pub)

            # User message input
            aliceMsg = input(bcolors.OKGREEN + "\nType a message to send to Bob: " + bcolors.ENDC)

            # Encrypt with Bob's public key
            aliceCipher = rsa.encrypt(aliceMsg.encode("utf-8"), bob_pub)

            # Package cipher + Alice public key
            data = [aliceCipher, alice_pub]

            # Send data
            clientSocket.send(pickle.dumps(data))
            print(bcolors.OKBLUE + "Encrypted message sent to Bob ✅" + bcolors.ENDC)

            # Receive Bob response
            bobResponse = clientSocket.recv(4096)
            if not bobResponse:
                print(bcolors.WARNING + "Bob disconnected." + bcolors.ENDC)
                break

            bobCipher = pickle.loads(bobResponse)

            print(bcolors.OKGREEN + "\nCipher text from Bob:" + bcolors.ENDC)
            print(bobCipher)

            # Decrypt Bob message
            bobMessage = rsa.decrypt(bobCipher, alice_priv).decode("utf-8")
            print(bcolors.OKCYAN + "\nDecrypted message from Bob:" + bcolors.ENDC)
            print(bcolors.BOLD + bobMessage + bcolors.ENDC)

    except Exception as e:
        print(bcolors.FAIL + f"\nERROR: {e}" + bcolors.ENDC)

    finally:
        clientSocket.close()
