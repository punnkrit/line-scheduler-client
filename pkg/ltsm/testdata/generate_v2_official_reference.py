#!/usr/bin/env python3
"""Generate an offline official Chrome 3.7.2 WASM V2 interoperability fixture.

Usage: python3 generate_v2_official_reference.py /path/to/unpacked/extension
Requires Node.js and Python cryptography. Downloads only a public pinned JS host
shim from OkLine; reads only the specified public extension assets. Uses no LINE
account, profile, login, network API, or session. The unmodified official WASM
performs all white-box operations. A temporary JS copy exposes existing exports
and synthesizes authenticated encrypted MIDs from public embedded key material.
"""

import base64
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


WASM_SHA256 = "58bb4e189ab9bbd7d72ed415258da36afd50e306cb019bab75329d4f5f1b65b3"
SANDBOX_SHA256 = "5c66cba945cc039d817e87fef2aa1e28c8adb7be0f94fca5b95bb6bcf5a07c94"
BRIDGE_SHA256 = "db5a9940866d1153e51c14f275439ae828be3d8106d4f086072f869c576b2a53"
BRIDGE_URL = (
    "https://raw.githubusercontent.com/NiceDayZc/OkLine/"
    "2e3437977368802edcc2219798b9d5333665ebca/okline/ltsm/ltsm_bridge.js"
)


def main(extension):
    assets = Path(extension) / "static" / "js"
    if hashlib.sha256((assets / "ltsm.wasm").read_bytes()).hexdigest() != WASM_SHA256:
        raise ValueError("Official WASM SHA-256 does not match the pinned reference")
    sandbox_bytes = (assets / "ltsmSandbox.js").read_bytes()
    if hashlib.sha256(sandbox_bytes).hexdigest() != SANDBOX_SHA256:
        raise ValueError("Official sandbox JavaScript SHA-256 does not match the pinned reference")
    with urllib.request.urlopen(BRIDGE_URL, timeout=30) as response:
        bridge_bytes = response.read()
    if hashlib.sha256(bridge_bytes).hexdigest() != BRIDGE_SHA256:
        raise ValueError("Public host shim SHA-256 does not match the pinned reference")
    with tempfile.TemporaryDirectory(prefix="line-v2-official-") as temporary:
        work = Path(temporary)
        shutil.copyfile(assets / "ltsm.wasm", work / "ltsm.wasm")
        sandbox = sandbox_bytes.decode("utf-8")
        marker = "function wS(e){return e instanceof fS().E2EEKey}"
        assert sandbox.count(marker) == 1
        sandbox = sandbox.replace(marker, "globalThis.__lineReference={module:fS};" + marker)
        (work / "ltsmSandbox.js").write_text(sandbox, encoding="utf-8")
        bridge = bridge_bytes.decode("utf-8")
        marker = "switch (req.op) {"
        assert bridge.count(marker) == 1
        bridge = bridge.replace(marker, marker + """
    case 'reference_mid_encrypt': {
      const mod = global.__lineReference.module();
      const sk = mod.SecureKey.loadKey(mod.HEAPU8.slice(7376, 7376 + 193));
      const key = new mod.AesKey(sk);
      const ciphertext = key.encrypt(new Uint8Array(Buffer.from(req.hex, 'hex')));
      // Encrypted MIDs use a four-byte GCM tag, unlike message ciphertext.
      const sealed = Buffer.from([...ciphertext.slice(0, -16), ...ciphertext.slice(-16, -12)]);
      return req.prefix + sealed.toString('base64url');
    }
""")
        (work / "ltsm_bridge.js").write_text(bridge, encoding="utf-8")
        process = subprocess.Popen(
            ["node", "--experimental-global-webcrypto", str(work / "ltsm_bridge.js")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            assert json.loads(process.stdout.readline()).get("ready")

            def call(op, **kwargs):
                process.stdin.write(json.dumps(dict(id=1, op=op, **kwargs)) + "\n")
                process.stdin.flush()
                reply = json.loads(process.stdout.readline())
                if "error" in reply:
                    raise RuntimeError(reply["error"])
                return reply["result"]

            recipient = "u" + "11" * 16
            sender = "u" + "22" * 16
            encrypted_recipient = call("reference_mid_encrypt", prefix="u", hex=recipient[1:])
            encrypted_sender = call("reference_mid_encrypt", prefix="u", hex=sender[1:])
            key_handle = call("curvekey_generate")
            sender_public = base64.b64decode(call("e2ee_public_key", keyId=key_handle))
            # Public RFC 7748 Bob test key. Only the official WASM sender key is random.
            receiver_private = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
            receiver = X25519PrivateKey.from_private_bytes(receiver_private)
            receiver_public = receiver.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            channel = call("e2ee_create_channel", keyId=key_handle, serverPubKeyB64=base64.b64encode(receiver_public).decode())
            plaintext = b'{"text":"official WASM synthetic reference"}'
            seq = 0x100000001
            ciphertext = base64.b64decode(call(
                "e2ee_encrypt_v2", channelId=channel, to=encrypted_recipient,
                **{"from": encrypted_sender}, senderKeyId=11, receiverKeyId=22,
                contentType=0, sequenceNumber=str(seq), plaintextB64=base64.b64encode(plaintext).decode(),
            ))
            shared = receiver.exchange(X25519PublicKey.from_public_bytes(sender_public))
            aad = recipient.encode() + sender.encode() + struct.pack(">IIII", 11, 22, 2, 0)
            aes_key = hashlib.sha256(shared + ciphertext[:16] + b"Key").digest()
            assert AESGCM(aes_key).decrypt(ciphertext[16:28], ciphertext[28:], aad) == plaintext
            assert int.from_bytes(ciphertext[16:24], "big") == seq
            fixture = dict(
                name="official-chrome-3.7.2", privateKey=receiver_private.hex(),
                peerPublicKey=sender_public.hex(), sharedSecret=shared.hex(),
                to=recipient, sender=sender, senderKeyID=11, receiverKeyID=22,
                contentType=0, sequence=seq, plaintext=plaintext.hex(),
                salt=ciphertext[:16].hex(), nonce=ciphertext[16:28].hex(),
                aad=aad.hex(), aesKey=aes_key.hex(), ciphertext=ciphertext.hex(),
                encryptedTo=encrypted_recipient, encryptedSender=encrypted_sender,
                wasmSHA256=WASM_SHA256, bridgeURL=BRIDGE_URL, bridgeSHA256=BRIDGE_SHA256,
            )
            target = Path(__file__).with_name("v2_official_reference.json")
            target.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")
            print(f"Wrote {target.name}; official WASM ciphertext independently decrypted by Python")
        finally:
            process.terminate()
            process.wait(timeout=10)


if __name__ == "__main__":
    main(sys.argv[1])
