from flask import Flask, jsonify, request
from jose import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import uuid

app = Flask(__name__)

# Function to generate RSA private and public keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serialize private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Extract public key from private key
    public_key = private_key.public_key()

    # Serialize public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key

# Generate RSA private and public keys
private_key_pem, public_key = generate_rsa_keys()

# Dummy user for authentication
dummy_user = {
    'username': 'john_doe',
    'user_id': 123
}

# Generate a Key ID (kid)
key_id = str(uuid.uuid4())

# Endpoint to get the JWKS (JSON Web Key Set)
@app.route('/jwks', methods=['GET'])
def get_jwks():
    global public_key, key_id

    # Create a JSON Web Key (JWK) with the current key ID
    jwk = {
        'kid': key_id,
        'alg': 'RS256',
        'kty': 'RSA',
        'use': 'sig',
        'n': public_key.public_numbers().n,
        'e': public_key.public_numbers().e
    }

    # Return a JSON Web Key Set containing the current JWK
    jwks = {'keys': [jwk]}
    return jsonify(jwks)

# Endpoint to get an encoded and signed JWT with a standard format
@app.route('/auth', methods=['GET'])
def get_encoded_jwt():
    global private_key_pem, key_id

    # Create a JWT with a standard format
    standard_jwt = jwt.encode(
        {'sub': dummy_user['user_id'], 'username': dummy_user['username']},
        private_key_pem,
        algorithm='RS256',
        headers={'kid': key_id}
    )

    return jsonify({'token': standard_jwt})

# Run the Flask application on port 8080
if __name__ == '__main__':
    app.run(debug=True, port=8080)
