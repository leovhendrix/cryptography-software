#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔════════════════════════════════════════════════════════════╗
║            P A R A D O X   3 3 0 7   v2.0                  ║
║      Easy Cryptography Suite — ZERO dependencies           ║
║   ChaCha20 | HMAC-SHA256 | scrypt | Pure Standard Library  ║
╚════════════════════════════════════════════════════════════╝
"""

import os, sys, base64, getpass, hashlib, hmac, secrets

MAGIC   = b"PDX3307"
VERSION = 2
SALT_LEN, NONCE_LEN, KEY_LEN = 32, 12, 32

# ---------------- ChaCha20 (RFC 8439) — pure Python, tested ----------------
def _rotl(v, n): return ((v << n) | (v >> (32 - n))) & 0xffffffff

def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = _rotl(s[b] ^ s[c], 7)

def _block(key, counter, nonce):
    consts = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    k = list(int.from_bytes(key[i*4:i*4+4], "little") for i in range(8))
    n = list(int.from_bytes(nonce[i*4:i*4+4], "little") for i in range(3))
    s = consts + k + [counter] + n
    work = s[:]
    for _ in range(10):
        _quarter(work, 0, 4,  8, 12); _quarter(work, 1, 5,  9, 13)
        _quarter(work, 2, 6, 10, 14); _quarter(work, 3, 7, 11, 15)
        _quarter(work, 0, 5, 10, 15); _quarter(work, 1, 6, 11, 12)
        _quarter(work, 2, 7,  8, 13); _quarter(work, 3, 4,  9, 14)
    out = b"".join(((work[i] + s[i]) & 0xffffffff).to_bytes(4, "little") for i in range(16))
    return out

def chacha20_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for block_num in range((len(data) + 63) // 64):
        ks = _block(key, block_num, nonce)
        chunk = data[block_num*64:(block_num+1)*64]
        out.extend(x ^ y for x, y in zip(chunk, ks))
    return bytes(out)

# ---------------- KDF: scrypt (built into Python) ----------------
def derive_key(password: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(password, salt=salt, n=2**15, r=8, p=1,
                          dklen=KEY_LEN, maxmem=256*1024*1024)

# ---------------- Encrypt / Decrypt (ChaCha20 + HMAC, authenticated) ----------------
def encrypt_bytes(data: bytes, password: bytes) -> bytes:
    salt   = secrets.token_bytes(SALT_LEN)
    nonce  = secrets.token_bytes(NONCE_LEN)
    key    = derive_key(password, salt)
    ct     = chacha20_xor(key, nonce, data)
    tag    = hmac.new(key, MAGIC + VERSION.to_bytes(1,"big") + salt + nonce + ct,
                      hashlib.sha256).digest()
    return MAGIC + bytes([VERSION]) + salt + nonce + ct + tag

def decrypt_bytes(blob: bytes, password: bytes) -> bytes:
    if not blob.startswith(MAGIC):
        raise ValueError("Not a PARADOX 3307 file.")
    if blob[7] != VERSION:
        raise ValueError("Unsupported version.")
    off = 8
    salt  = blob[off:off+SALT_LEN]
    nonce = blob[off+SALT_LEN:off+SALT_LEN+NONCE_LEN]
    ct    = blob[off+SALT_LEN+NONCE_LEN:-32]
    tag   = blob[-32:]
    key   = derive_key(password, salt)
    expect = hmac.new(key, MAGIC + blob[7:8] + salt + nonce + ct,
                      hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expect):
        raise ValueError("Wrong password or file corrupted.")
    return chacha20_xor(key, nonce, ct)

# ---------------- Helpers ----------------
def read_file(p):
    with open(p, "rb") as f: return f.read()

def write_file(p, d):
    with open(p, "wb") as f: f.write(d)

def get_pw(confirm=False):
    pw = getpass.getpass("  Password: ").encode()
    if confirm:
        if pw != getpass.getpass("  Confirm : ").encode():
            print("  [!] Passwords do not match."); return None
    if len(pw) < 8: print("  [!] Warning: weak password (<8 chars).")
    return pw

def pause():
    input("\n  Press ENTER to return to menu...")

# ---------------- Menu Actions ----------------
def act_encrypt():
    inp = input("  File to encrypt : ").strip().strip('"')
    if not os.path.isfile(inp): print("  [!] File not found."); return pause()
    pw = get_pw(confirm=True)
    if pw is None: return pause()
    out = inp + ".pdx"
    write_file(out, encrypt_bytes(read_file(inp), pw))
    print(f"\n  [+] DONE! Encrypted file: {out}")
    pause()

def act_decrypt():
    inp = input("  File to decrypt (.pdx): ").strip().strip('"')
    if not os.path.isfile(inp): print("  [!] File not found."); return pause()
    pw = get_pw()
    try:
        out = inp[:-4] if inp.endswith(".pdx") else inp + ".dec"
        write_file(out, decrypt_bytes(read_file(inp), pw))
        print(f"\n  [+] DONE! Decrypted file: {out}  (verified OK)")
    except Exception as e:
        print(f"\n  [-] FAILED: {e}")
    pause()

def act_hash():
    inp = input("  File to hash: ").strip().strip('"')
    if not os.path.isfile(inp): print("  [!] File not found."); return pause()
    d = read_file(inp)
    print(f"\n  SHA-256   : {hashlib.sha256(d).hexdigest()}")
    print(f"  SHA-512   : {hashlib.sha512(d).hexdigest()}")
    print(f"  SHA3-256  : {hashlib.sha3_256(d).hexdigest()}")
    print(f"  BLAKE2b   : {hashlib.blake2b(d, digest_size=64).hexdigest()}")
    pause()

def act_hmac():
    inp = input("  File: ").strip().strip('"')
    if not os.path.isfile(inp): print("  [!] File not found."); return pause()
    key = getpass.getpass("  Secret key: ").encode()
    print(f"\n  HMAC-SHA256: {hmac.new(key, read_file(inp), hashlib.sha256).hexdigest()}")
    pause()

def act_genpass():
    n   = int(input("  How many passwords? [5]: ") or 5)
    ln  = int(input("  Length? [20]: ") or 20)
    sy  = input("  Include symbols? (y/n) [y]: ").strip().lower() or "y"
    abc = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    if sy == "y": abc += "!@#$%^&*()-_=+"
    print()
    for _ in range(n):
        print("  " + "".join(secrets.choice(abc) for _ in range(ln)))
    pause()

def act_keygen():
    key = secrets.token_bytes(KEY_LEN)
    print(f"\n  Random 256-bit key: {base64.b64encode(key).decode()}")
    pause()

def act_wipe():
    inp = input("  File to DESTROY forever: ").strip().strip('"')
    if not os.path.isfile(inp): print("  [!] File not found."); return pause()
    if input("  Type WIPE to confirm (cannot undo!): ").strip() != "WIPE":
        print("  [!] Cancelled."); return pause()
    size = os.path.getsize(inp)
    with open(inp, "r+b") as f:
        for _ in range(3):
            f.seek(0)
            left = size
            while left > 0:
                chunk = os.urandom(min(left, 1 << 20))
                f.write(chunk); left -= len(chunk)
            f.flush(); os.fsync(f.fileno())
    os.remove(inp)
    print(f"\n  [+] {inp} overwritten 3 times and deleted.")
    pause()

def act_info():
    print("""
  ─────────────────────────────────────────────
  Cipher     : ChaCha20 (RFC 8439, stream cipher)
  Auth       : HMAC-SHA256 (encrypt-then-MAC)
  KDF        : scrypt (N=2^15, r=8, ~32 MiB)
  Randomness : OS CSPRNG (secrets / os.urandom)
  Compare    : constant-time (hmac.compare_digest)
  File format: PDX3307 | ver | salt | nonce | ct | tag
  ─────────────────────────────────────────────""")
    pause()

# ---------------- Main Menu ----------------
BANNER = r"""
  ██████╗  █████╗ ██████╗  █████╗ ██████╗  ██████╗ ██╗  ██╗
  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝ ██╔════╝ ╚██╗██╔╝
  ██████╔╝███████║██║  ██║███████║██║  ███╗██║        ╚███╔╝
  ██╔═══╝ ██╔══██║██║  ██║██╔══██║██║   ██║██║       ██╔██╗
  ██║     ██║  ██║██████╔╝██║  ██║╚██████╔╝╚██████╗ ██╔╝ ██╗
  ╚═╝     ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
                     3 3 0 7   —  EASY CRYPTO SUITE
"""

MENU = """
  ╔═══════════════════════════════════════╗
  ║           MAIN  MENU                  ║
  ╠═══════════════════════════════════════╣
  ║  [1] Encrypt a file                   ║
  ║  [2] Decrypt a file                   ║
  ║  [3] Hash a file (checksums)          ║
  ║  [4] HMAC (verify data)               ║
  ║  [5] Generate passwords               ║
  ║  [6] Generate 256-bit key             ║
  ║  [7] WIPE a file (destroy forever)    ║
  ║  [8] Security info                    ║
  ║  [0] Exit                             ║
  ╚═══════════════════════════════════════╝"""

ACTIONS = {"1": act_encrypt, "2": act_decrypt, "3": act_hash,
           "4": act_hmac, "5": act_genpass, "6": act_keygen,
           "7": act_wipe, "8": act_info}

def main():
    while True:
        print(BANNER)
        print(MENU)
        choice = input("\n  Choose an option: ").strip()
        if choice == "0":
            print("  Goodbye!"); break
        action = ACTIONS.get(choice)
        if action: action()
        else: print("  [!] Invalid option, try again.")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\n  Goodbye!")