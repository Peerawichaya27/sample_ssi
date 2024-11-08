const { ethers } = require("ethers");
const fs = require("fs");

// Load the ABI from the JSON file
const abi = JSON.parse(fs.readFileSync('contract_abi.json', 'utf-8'));

// Set up provider and contract details
const provider = new ethers.providers.JsonRpcProvider('http://127.0.0.1:8545'); // Ganache
const contractAddress = '0x0feB17FC3b67D9Af7Fd15A579FF4f63a7249FF89'; // Replace with your contract address

// Create a contract instance
const contract = new ethers.Contract(contractAddress, abi, provider);

// Example: verify VP signature
async function verifyVP(vp, publicKey) {
    const message = JSON.stringify(vp, null, 2);
    const signature = vp.proof.jws;

    // Decode the JWS
    const decodedSignature = Buffer.from(signature, 'base64');

    // Verify the signature using ethers.js
    const isValid = await ethers.utils.verifyMessage(message, decodedSignature);

    return isValid;
}

// Example usage
const publicKey = "0xYourPublicKey"; // Replace with actual public key
const vp = {/* Your VP object */}; // Replace with the VP you retrieved

verifyVP(vp, publicKey).then(isValid => {
    console.log("Verification result:", isValid);
}).catch(err => {
    console.error("Verification failed:", err);
});
