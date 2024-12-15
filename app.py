from flask import Flask, render_template, request, jsonify
import random
import base64
from math import gcd
from sympy import mod_inverse

app = Flask(__name__)




# Helper Functions
def is_prime(num):
    if num <= 1:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True


def generate_prime_candidate(start, end):
    candidate = random.randint(start, end)
    while not is_prime(candidate):
        candidate = random.randint(start, end)
    return candidate


# RSA Helper Functions
def mod_inverse(e, phi):
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = egcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, x, _ = egcd(e, phi)
    return x % phi


def generate_rsa_keys():
    p = generate_prime_candidate(100, 300)
    q = generate_prime_candidate(100, 300)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))


def rsa_encrypt(message, pub_key):
    e, n = pub_key
    ciphertext = []

    for char in message:
        char_code = ord(char)
        encrypted_char = pow(char_code, e, n)
        ciphertext.append(encrypted_char)

    encrypted_bytes = b''.join(chunk.to_bytes((chunk.bit_length() + 7) // 8, byteorder='big') for chunk in ciphertext)
    return base64.b64encode(encrypted_bytes).decode('utf-8')


def rsa_decrypt(ciphertext, priv_key):
    d, n = priv_key
    ciphertext_bytes = base64.b64decode(ciphertext)

    ciphertext_chunks = []
    chunk_size = (n.bit_length() + 7) // 8
    for i in range(0, len(ciphertext_bytes), chunk_size):
        chunk = int.from_bytes(ciphertext_bytes[i:i + chunk_size], byteorder='big')
        ciphertext_chunks.append(chunk)

    decrypted_message = ''.join([chr(pow(chunk, d, n)) for chunk in ciphertext_chunks])

    # Check if the decrypted message contains valid ASCII characters only
    if all(32 <= ord(char) <= 126 for char in decrypted_message):
        return decrypted_message
    else:
        return None  # Return None if the message contains non-ASCII characters


# ElGamal Helper Functions
def generate_elgamal_keys():
    p = generate_prime_candidate(100, 300)
    g = random.randint(2, p - 1)
    x = random.randint(1, p - 2)
    h = pow(g, x, p)
    public_key = (p, g, h)
    private_key = (p, g, x)
    return public_key, private_key


def elgamal_encrypt(message, pub_key):
    p, g, h = pub_key
    y = random.randint(1, p - 2)
    c1 = pow(g, y, p)
    ciphertext = []
    for char in message:
        char_code = ord(char)
        c2 = (char_code * pow(h, y, p)) % p
        ciphertext.append((c1, c2))
    return base64.b64encode(str(ciphertext).encode()).decode()


def elgamal_decrypt(ciphertext, priv_key):
    p, g, x = priv_key
    ciphertext = eval(base64.b64decode(ciphertext).decode())
    decrypted_message = []
    for c1, c2 in ciphertext:
        s = pow(c1, x, p)
        char_code = (c2 * mod_inverse(s, p)) % p
        decrypted_message.append(chr(char_code))
    return ''.join(decrypted_message)


# Generate keys for both RSA and ElGamal
rsa_public_key, rsa_private_key = generate_rsa_keys()
elgamal_public_key, elgamal_private_key = generate_elgamal_keys()

# Print generated keys in the console
print(f"RSA Public Key: {rsa_public_key}")
print(f"RSA Private Key: {rsa_private_key}")
print(f"ElGamal Public Key: {elgamal_public_key}")
print(f"ElGamal Private Key: {elgamal_private_key}")

encrypted_message_with_token = ""


# Routes
@app.route('/sender')
def sender():
    return render_template('sender.html')


@app.route('/receiver')
def receiver():
    return render_template('receiver.html')


@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    message = request.form['message']
    encryption_type = request.form['encryption_type']
    if encryption_type == 'RSA':
        pub_key = request.form['public_key']
        e, n = map(int, pub_key.split(","))
        encrypted_message = rsa_encrypt(message, (e, n))
    elif encryption_type == 'ElGamal':
        encrypted_message = elgamal_encrypt(message, elgamal_public_key)
    return jsonify(encrypted_message=encrypted_message)


@app.route('/send_to_receiver', methods=['POST'])
def send_to_receiver():
    global encrypted_message_with_token
    cipher_text = request.form['cipher_text']
    token = request.form['token']
    encrypted_message_with_token = f"{cipher_text}:{token}"
    return jsonify(status="Message sent successfully!")


@app.route('/get_encrypted_message')
def get_encrypted_message():
    return jsonify(encrypted_message_with_token=encrypted_message_with_token)


@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    encrypted_message = request.form['encrypted_message']
    encryption_type = request.form['encryption_type']

    if encryption_type == 'RSA':
        priv_key = request.form['private_key']
        d, n = map(int, priv_key.split(","))
        decrypted_message = rsa_decrypt(encrypted_message, (d, n))
    elif encryption_type == 'ElGamal':
        decrypted_message = elgamal_decrypt(encrypted_message, elgamal_private_key)

    if decrypted_message is None:
        return jsonify(decrypted_message="Incorrect key!")
    else:
        return jsonify(decrypted_message=decrypted_message)


if __name__ == "__main__":
    app.run(debug=True)

