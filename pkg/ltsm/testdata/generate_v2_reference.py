#!/usr/bin/env python3
"""Regenerate synthetic V2 known answers with Python cryptography, independently of Go.

Run from any directory with Python cryptography installed. No LINE access occurs.
The X25519 inputs are the public RFC 7748 section 6.1 test keys, not account keys.

Protocol: LY Corporation, LINE Encryption Overview v2.2, pp. 5-7:
https://www.lycorp.co.jp/en/privacy-security/line-encryption-whitepaper-ver2.2.pdf
Byte encoding corroboration: CHRLINE generateAAD/getIntBytes and OkLine key_id_to_bytes:
https://github.com/DeachSword/CHRLINE/blob/3ee320668e2da6fc04b50e2054b880e86d23434d/CHRLINE/e2ee.py
https://github.com/NiceDayZc/OkLine/blob/2e3437977368802edcc2219798b9d5333665ebca/okline/e2ee_crypto.py

These vectors validate the published algorithm, not Chrome's opaque key loader,
white-box MID processing, saved-session compatibility, or live delivery.
"""

import hashlib
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def generate():
    alice_private = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    bob_private = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    )
    alice = X25519PrivateKey.from_private_bytes(alice_private)
    bob = X25519PrivateKey.from_private_bytes(bob_private)
    shared = alice.exchange(bob.public_key())
    assert shared.hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    inputs = [
        ("direct-text", "u0123456789abcdef0123456789abcdef", 11, 22, 0, 1,
         b'{"text":"synthetic reference"}'),
        ("group-media", "c0123456789abcdef0123456789abcdef", 0x1020304, 0x7ffffffe,
         14, 0x100000001, b'{"fileName":"synthetic.txt","keyMaterial":"fixture"}'),
        ("empty", "r0123456789abcdef0123456789abcdef", 0x7fffffff, 0, 15,
         0x102030405060708, b""),
    ]
    vectors = []
    for index, (name, recipient, sid, rid, content_type, seq, plaintext) in enumerate(inputs):
        sender = "ufedcba9876543210fedcba9876543210"
        salt = bytes(range(index, index + 16))
        nonce = struct.pack(">Q", seq) + bytes.fromhex("aabbccdd")
        aad = recipient.encode("ascii") + sender.encode("ascii")
        aad += struct.pack(">IIII", sid, rid, 2, content_type)
        key = hashlib.sha256(shared + salt + b"Key").digest()
        sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
        vectors.append(dict(
            name=name,
            privateKey=alice_private.hex(),
            peerPublicKey=bob.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
            sharedSecret=shared.hex(),
            to=recipient, sender=sender, senderKeyID=sid, receiverKeyID=rid,
            contentType=content_type, sequence=seq,
            plaintext=plaintext.hex(), salt=salt.hex(), nonce=nonce.hex(),
            aad=aad.hex(), aesKey=key.hex(), ciphertext=(salt + nonce + sealed).hex(),
        ))
    return vectors


if __name__ == "__main__":
    target = Path(__file__).with_name("v2_reference.json")
    target.write_text(json.dumps(generate(), indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {target.name}: 3 synthetic known-answer vectors")
