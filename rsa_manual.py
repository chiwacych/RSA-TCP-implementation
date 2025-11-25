"""
Manual RSA Implementation
As per project requirements:
- Generate 512-bit primes p and q
- Calculate n = p * q (1024-bit key)
- Calculate φ(n) = (p-1)(q-1)
- Choose e = 65537 (standard public exponent)
- Calculate d such that e*d ≡ 1 (mod φ(n))
- Encrypt: C = M^e mod n
- Decrypt: M = C^d mod n
"""

import secrets
import math


def is_prime(n, k=50):
    """
    Miller-Rabin primality test
    Returns True if n is probably prime (certainty 1-1/2^k)
    k=50 gives certainty 1-1/2^50 as per requirements
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def generate_prime(bit_length=512):
    """
    Generate a random prime number with specified bit length
    Uses SecureRandom (secrets module) as per requirements
    """
    print(f"  Generating {bit_length}-bit prime...")
    while True:
        # Generate random number with exact bit length
        # Ensure the number has exactly bit_length bits
        candidate = secrets.randbits(bit_length)
        # Set the most significant bit to ensure bit_length
        candidate |= (1 << (bit_length - 1))
        # Set the least significant bit to ensure it's odd
        candidate |= 1
        
        if is_prime(candidate, k=50):
            print(f"  ✓ Prime found")
            return candidate


def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm
    Returns (gcd, x, y) such that a*x + b*y = gcd
    """
    if a == 0:
        return b, 0, 1
    
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd, x, y


def mod_inverse(e, phi):
    """
    Calculate modular multiplicative inverse
    Returns d such that (e * d) ≡ 1 (mod phi)
    """
    gcd, x, _ = extended_gcd(e, phi)
    
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    
    return x % phi


def generate_keypair(bit_length=512):
    """
    Generate RSA key pair
    Args:
        bit_length: Bit length for p and q (512 for 1024-bit RSA)
    Returns:
        ((e, n), (d, n)) - public key, private key
    """
    print("\n=== RSA Key Generation ===")
    print(f"Generating {bit_length*2}-bit RSA keys...")
    
    # Step 1: Generate two distinct primes p and q
    print("\nStep 1: Generating prime p (512 bits)...")
    p = generate_prime(bit_length)
    
    print("\nStep 2: Generating prime q (512 bits)...")
    q = generate_prime(bit_length)
    
    # Ensure p and q are different
    while p == q:
        print("  p and q are equal, regenerating q...")
        q = generate_prime(bit_length)
    
    # Step 2: Calculate n = p * q
    print("\nStep 3: Calculating n = p * q...")
    n = p * q
    print(f"  n = {n}")
    print(f"  n bit length: {n.bit_length()} bits")
    
    # Step 3: Calculate φ(n) = (p-1)(q-1)
    print("\nStep 4: Calculating φ(n) = (p-1)(q-1)...")
    phi = (p - 1) * (q - 1)
    print(f"  φ(n) calculated")
    
    # Step 4: Choose e (public exponent)
    # Standard choice is 65537 (2^16 + 1)
    e = 65537
    print(f"\nStep 5: Choosing public exponent e = {e}")
    
    # Verify gcd(e, phi) = 1
    if math.gcd(e, phi) != 1:
        raise ValueError("e and phi(n) are not coprime")
    
    # Step 5: Calculate d (private exponent)
    # d is the modular multiplicative inverse of e modulo phi
    print("\nStep 6: Calculating private exponent d...")
    d = mod_inverse(e, phi)
    print("  d calculated successfully")
    
    # Verify e*d ≡ 1 (mod phi)
    assert (e * d) % phi == 1, "Key generation verification failed"
    
    print("\n✓ RSA key pair generated successfully!")
    print(f"  Public Key: (e={e}, n={n.bit_length()}-bit)")
    print(f"  Private Key: (d={d.bit_length()}-bit, n={n.bit_length()}-bit)")
    
    # Return (public_key, private_key)
    return ((e, n), (d, n))


def encrypt(message, public_key):
    """
    Encrypt message using RSA public key
    C = M^e mod n
    Args:
        message: bytes to encrypt
        public_key: (e, n) tuple
    Returns:
        Encrypted integer (ciphertext)
    """
    e, n = public_key
    
    # Convert message bytes to integer
    message_int = int.from_bytes(message, byteorder='big')
    
    # Ensure message is smaller than n
    if message_int >= n:
        raise ValueError("Message too large for key size")
    
    # Encrypt: C = M^e mod n
    ciphertext = pow(message_int, e, n)
    
    return ciphertext


def decrypt(ciphertext, private_key):
    """
    Decrypt ciphertext using RSA private key
    M = C^d mod n
    Args:
        ciphertext: integer to decrypt
        private_key: (d, n) tuple
    Returns:
        Decrypted bytes (plaintext)
    """
    d, n = private_key
    
    # Decrypt: M = C^d mod n
    message_int = pow(ciphertext, d, n)
    
    # Convert integer back to bytes
    # Calculate number of bytes needed
    byte_length = (message_int.bit_length() + 7) // 8
    message_bytes = message_int.to_bytes(byte_length, byteorder='big')
    
    return message_bytes


def encrypt_string(message_str, public_key):
    """
    Encrypt a string message
    Args:
        message_str: string to encrypt
        public_key: (e, n) tuple
    Returns:
        Encrypted integer
    """
    message_bytes = message_str.encode('utf-8')
    return encrypt(message_bytes, public_key)


def decrypt_to_string(ciphertext, private_key):
    """
    Decrypt ciphertext to string
    Args:
        ciphertext: integer to decrypt
        private_key: (d, n) tuple
    Returns:
        Decrypted string
    Raises:
        ValueError: If decrypted data is not valid UTF-8
    """
    try:
        message_bytes = decrypt(ciphertext, private_key)
        return message_bytes.decode('utf-8')
    except UnicodeDecodeError as e:
        raise ValueError(
            f"Decryption produced invalid UTF-8 data. "
            f"This usually means:\n"
            f"1. Wrong private key (d, n) for this ciphertext\n"
            f"2. Ciphertext was encrypted with a different key\n"
            f"3. Ciphertext is corrupted or invalid\n\n"
            f"Technical details: {str(e)}"
        )


# Example usage and testing
if __name__ == "__main__":
    print("Testing Manual RSA Implementation\n")
    
    # Generate keys
    public_key, private_key = generate_keypair(bit_length=512)
    
    # Test encryption/decryption
    print("\n=== Testing Encryption/Decryption ===")
    test_message = "Hello, RSA!"
    print(f"Original message: {test_message}")
    
    # Encrypt
    print("\nEncrypting...")
    ciphertext = encrypt_string(test_message, public_key)
    print(f"Ciphertext (integer): {ciphertext}")
    print(f"Ciphertext bit length: {ciphertext.bit_length()} bits")
    
    # Decrypt
    print("\nDecrypting...")
    decrypted_message = decrypt_to_string(ciphertext, private_key)
    print(f"Decrypted message: {decrypted_message}")
    
    # Verify
    if test_message == decrypted_message:
        print("\n✓ SUCCESS: Encryption/Decryption working correctly!")
    else:
        print("\n✗ FAILED: Messages don't match!")
