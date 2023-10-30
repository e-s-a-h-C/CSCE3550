from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import sqlite3
import base64
import jwt
import datetime
import requests

app = Flask(__name__)

def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def create_or_open_db():
    connection = sqlite3.connect('totally_not_my_privateKeys.db')
    with connection:
        cursor = connection.cursor()

        # Create a table to store keys if it doesn't exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS keys (
                            kid INTEGER PRIMARY KEY AUTOINCREMENT,
                            key BLOB NOT NULL,
                            exp INTEGER NOT NULL
                        )''')

        # Check if keys exist, if not, generate and insert them
        cursor.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]
        if count == 0:
            # Generate a key that expires now (or less)
            expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            expired_pem = expired_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (expired_pem, int(datetime.datetime.utcnow().timestamp())))

            # Generate a key that expires in 1 hour (or more)
            future_exp = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            future_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            future_pem = future_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (future_pem, int(future_exp.timestamp())))

    connection.close()

def get_key_from_db(kid):
    connection = sqlite3.connect('totally_not_my_privateKeys.db')
    with connection:
        cursor = connection.cursor()
        cursor.execute("SELECT key FROM keys WHERE kid=?", (kid,))
        key = cursor.fetchone()
        if key:
            return key[0]
        return None
    
def get_jwks():
    jwks_response = requests.get('http://localhost:8080/.well-known/jwks.json')
    if jwks_response.status_code == 200:
        return jwks_response.json()
    return None

@app.route('/auth', methods=['POST'])
def auth():
    kid = request.args.get('kid', '1')  # Replace '1' with the appropriate kid value
    expired_param = request.args.get('expired')

    key_data = get_key_from_db(kid)
    if key_data:
        private_key = serialization.load_pem_private_key(key_data, password=None)
        token_payload = {
            "user": "username",
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }

        if expired_param is not None:
            token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)

        encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256")
        return encoded_jwt, 200

    return "Key not found", 404



@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    keys = []
    connection = sqlite3.connect('totally_not_my_privateKeys.db')
    with connection:
        cursor = connection.cursor()
        cursor.execute("SELECT key, exp FROM keys WHERE exp > ?", (int(datetime.datetime.utcnow().timestamp()),))
        key_rows = cursor.fetchall()
        for key_data, exp in key_rows:
            private_key = serialization.load_pem_private_key(key_data, password=None)
            public_key = private_key.public_key()
            numbers = public_key.public_numbers()
            jwk = {
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": str(exp),  # Using expiration time as Key ID for unique identification
                "n": int_to_base64(numbers.n),
                "e": int_to_base64(numbers.e)
            }
            keys.append(jwk)

    jwks = {"keys": keys}  # Wrap keys in a dictionary under the "keys" key

    return jsonify(jwks)  # Return the complete JWKS object

if __name__ == '__main__':
    create_or_open_db()
    app.run(host='localhost', port=8080)
