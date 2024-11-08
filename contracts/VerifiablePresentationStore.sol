// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VerifiablePresentationStore {
    struct VerifiablePresentation {
        string vp; // Store the VP as a string
        address owner; // Store the address of the owner
    }

    struct DIDDocument {
        string publicKey; // Store public key
    }

    mapping(bytes32 => VerifiablePresentation) public presentations; // Mapping for VPs
    mapping(address => DIDDocument) public didDocuments; // Mapping for DID documents

    event PresentationStored(bytes32 indexed vpHash, string vp, address indexed owner);
    event DIDDocumentStored(address indexed owner, string publicKey);

    // Function to store the DID document
    function storeDIDDocument(string memory _publicKey) public {
        didDocuments[msg.sender] = DIDDocument(_publicKey);
        emit DIDDocumentStored(msg.sender, _publicKey);
    }

    // Function to store a VP
    function storeVP(string memory _vp) public {
        require(bytes(_vp).length > 0, "VP cannot be empty");
        bytes32 vpHash = keccak256(abi.encodePacked(_vp)); // Generate a hash of the VP
        presentations[vpHash] = VerifiablePresentation(_vp, msg.sender); // Store VP
        emit PresentationStored(vpHash, _vp, msg.sender); // Emit event
    }

    // Function to check if a VP exists
    function vpExists(bytes32 _vpHash) public view returns (bool) {
        return bytes(presentations[_vpHash].vp).length > 0; // Check if VP is stored
    }

    // Function to retrieve the DID document
    function getDIDDocument(address _owner) public view returns (string memory) {
        return didDocuments[_owner].publicKey; // Retrieve public key
    }
}
