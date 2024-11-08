from flask import Flask, request, jsonify, render_template
import json
from datetime import datetime, timezone
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from web3 import Web3
import hashlib

app = Flask(__name__)

# Connect to Ganache blockchain
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))  # Change port if necessary
contract_address = '0x4F45Db41b8804C02816b057e9eeb3292fE07F9AF'  # Replace with your deployed contract address
with open('contract_abi.json', 'r') as abi_file:
    contract_abi = json.load(abi_file)
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# Private key for signing transactions (replace with your actual private key)
private_key = '0x00e0ef45b0eeaf49ffd300e7e2a3acc29d36ed42d258c5b30e0e51196913a169'  # Replace with your private key
account = w3.eth.account.from_key(private_key)

# Global variable to act as a wallet for storing VCs
wallet = []

class CredentialIssuer:
    def __init__(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()

    def get_public_key(self):
        public_key = self.private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()  # Return the public key in hexadecimal format

    def create_did_document(self, public_key):
        return {
            "@context": "https://w3id.org/did/v1",
            "id": "did:university:student123",
            "publicKey": [
                {
                    "id": "did:university:student123#key-1",
                    "type": "Ed25519VerificationKey2018",
                    "controller": "did:university:student123",
                    "publicKeyBase58": base64.b64encode(bytes.fromhex(public_key)).decode('utf-8')  # Convert to base58
                }
            ],
            "authentication": [
                {
                    "type": "Ed25519SignatureAuthentication2018",
                    "publicKey": "did:university:student123#key-1"
                }
            ]
        }

    def issue_credential(self, subject_id, subject_name):
        vc = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": f"http://university.edu/credentials/student-credential-{subject_id}",
            "type": ["VerifiableCredential", "StudentCredential"],
            "issuer": "did:university:issuer123",
            "issuanceDate": datetime.now(timezone.utc).isoformat() + "Z",
            "credentialSubject": {
                "id": f"did:university:student{subject_id}",
                "name": subject_name
            }
        }
        
        # Create proof
        proof = {
            "type": "Ed25519Signature2020",
            "created": datetime.now(timezone.utc).isoformat() + "Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"did:university:issuer123#key-1"
        }

        # Sign the VC
        vc_json = json.dumps(vc, sort_keys=True).encode()
        signature = self.private_key.sign(vc_json)
        proof["jws"] = base64.urlsafe_b64encode(signature).decode('utf-8')
        
        vc["proof"] = proof
        
        return vc

class UserAgent:
    def __init__(self, private_key):
        self.private_key = private_key

    def generate_verifiable_presentation(self, vc):
        vp = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": "VerifiablePresentation",
            "verifiableCredential": [vc],
            "proof": {}
        }

        proof = {
            "type": "Ed25519Signature2020",
            "created": datetime.now(timezone.utc).isoformat() + "Z",
            "proofPurpose": "authentication",
            "verificationMethod": "did:university:student123#key-1",
            "challenge": "some-challenge-value",
            "domain": "university.edu"
        }

        vp_json = json.dumps(vp, sort_keys=True).encode()
        signature = self.private_key.sign(vp_json)
        proof["jws"] = base64.urlsafe_b64encode(signature).decode('utf-8')

        vp["proof"] = proof
        
        return vp

# Create instances of issuer and user agent
issuer = CredentialIssuer()
user_agent = UserAgent(issuer.private_key)

@app.route('/')
def home():
    return render_template('index.html')  # Serve the HTML file

@app.route('/create-vc', methods=['POST'])
def create_vc():
    data = request.json
    student_id = data['studentId']
    student_name = data['studentName']
    vc = issuer.issue_credential(student_id, student_name)

    # Create the public key as a string
    public_key = issuer.get_public_key()  # Get public key as a string

    # Store the DID document on the blockchain
    store_did_document(public_key)  # Pass the public key string

    # Store the VC in the wallet
    wallet.append(vc)

    return jsonify(vc), 201  # Only return the VC

def store_did_document(public_key):
    # Call the storeDIDDocument function in the smart contract
    transaction = contract.functions.storeDIDDocument(public_key).build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': 2000000,
        'gasPrice': w3.to_wei('50', 'gwei'),
    })

    signed_txn = w3.eth.account.sign_transaction(transaction, private_key)
    txn_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    txn_receipt = w3.eth.wait_for_transaction_receipt(txn_hash)

    if txn_receipt.status == 1:
        print("DID Document successfully stored in blockchain!")
    else:
        print("Transaction failed.")

@app.route('/create-vp', methods=['POST'])
def create_vp():
    if len(wallet) == 0:
        return jsonify({"error": "No credentials found in wallet"}), 400

    # Use the latest VC from the wallet
    latest_entry = wallet[-1]  # Get the last stored VC
    vc = latest_entry

    vp = user_agent.generate_verifiable_presentation(vc)

    # Calculate the VP hash
    vp_hash = hashlib.sha256(json.dumps(vp, sort_keys=True).encode()).hexdigest()
    print(f"VP Hash: {vp_hash}")  # Debug: Show the VP hash

    # Store the VP on the blockchain
    txn_receipt = store_vp_on_blockchain(vp)

    if txn_receipt is None:
        return jsonify({"error": "Failed to store VP on the blockchain"}), 500

    return jsonify({"vp": vp, "vpHash": vp_hash}), 201  # Return VP and its hash

def store_vp_on_blockchain(vp):
    vp_json = json.dumps(vp, sort_keys=True)  # Convert VP to JSON
    vp_hash = hashlib.sha256(vp_json.encode()).hexdigest()  # Generate hash of the VP 

    transaction = contract.functions.storeVP(vp_hash).build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': 2000000,
        'gasPrice': w3.to_wei('50', 'gwei'),
    })

    signed_txn = w3.eth.account.sign_transaction(transaction, private_key)
    txn_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    txn_receipt = w3.eth.wait_for_transaction_receipt(txn_hash)

    if txn_receipt.status == 1:
        print("VP successfully stored in blockchain!")
    else:
        print("Transaction failed.")

    return txn_receipt

@app.route('/check-vp', methods=['POST'])
def check_vp():
    data = request.json
    vp_hash = data['vpHash']  # Expecting the hash of the VP to check

    # Convert the string hash to bytes32
    vp_hash_bytes32 = Web3.keccak(text=vp_hash)  # Ensure the hash is in the right format

    try:
        # Call the contract function to check if the VP exists
        exists = contract.functions.vpExists(vp_hash_bytes32).call()
        return jsonify({"exists": exists})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
