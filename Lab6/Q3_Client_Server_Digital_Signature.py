
# ======================================================================
# 1. FULL QUESTION
# ======================================================================
# Lab Exercises 3:
# Try the same digital-signature process in a client-server-based scenario
# and record your observation and analysis.
#
# ======================================================================
# 2. QUESTION / CONTEXT EXPLANATION
# ======================================================================
# A client sends a message and its digital signature to a server. The
# server verifies the signature using the sender's public key and accepts
# the message only when verification succeeds.
#
# ======================================================================
# 3. THEORY AND FORMULAS
# ======================================================================
# Signature:
#   signature = Sign(private_key, message)
# Verification:
#   valid = Verify(public_key, message, signature)
#
# A secure signature scheme guarantees:
# - Integrity: modified messages fail verification.
# - Authenticity: only the private-key holder should create valid signs.
# - Non-repudiation support: signatures can provide evidence of origin,
#   subject to key protection and legal context.
#
# ======================================================================
# 4. DETAILED COMMENTS
# ======================================================================
# The server should never trust the received message before verification.
# It should validate message format, handle malformed signatures, and log
# verification results without exposing private keys.
#
# ======================================================================
# 5. ENCRYPTION / DECRYPTION LOGIC
# ======================================================================
# Digital signatures are not encryption. The message remains readable;
# the signature proves that the message was signed by the private-key owner.
#
# ======================================================================
# 6. BRUTE-FORCE / ATTACK EXERCISES
# ======================================================================
# - Modify the message in transit and observe rejection.
# - Modify one signature byte and observe rejection.
# - Replay a valid signed message and discuss timestamps/nonces.
# - Test malformed or oversized input handling.
#
# ======================================================================
# 7. CHARACTER MAPPING AND ASSUMPTIONS
# ======================================================================
# Messages are encoded as UTF-8 bytes. The implementation may use a
# simplified educational signature scheme; production systems should use
# RSA-PSS, Ed25519, or another standardized construction.
# ======================================================================

"""
LAB 6 - DIGITAL SIGNATURE
QUESTION 3

Client-server digital signature demonstration.

The client:
1. Creates a document.
2. Signs it using an RSA private key.
3. Sends document, signature, and public key to server.

The server:
1. Receives the document and signature.
2. Verifies the RSA signature.
3. Reports whether the document is authentic and unchanged.

Install:
    pip install cryptography

Run server first, then client.
"""

# This file is the server/client launcher explanation.
# Use the two separate files generated with this question:
# Q3_Digital_Signature_Server.py
# Q3_Digital_Signature_Client.py

print("Run Q3_Digital_Signature_Server.py in Terminal 1.")
print("Run Q3_Digital_Signature_Client.py in Terminal 2.")
