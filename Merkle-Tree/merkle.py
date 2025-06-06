import hashlib
import math 
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import re

# Constants indicating node direction in proof
LEFT = '0'
RIGHT = '1'

# Global list to store Merkle tree leaf hashes
leaf_hashes = []

# Expected argument count per command
ARG_COUNT = {1:1, 2:0, 3:1, 4:2, 5:0, 6:1, 7:3}

# Regular expressions for different commands
TOKEN_RE = re.compile(r'^([1-5])(?: ([^ ]+))*$')
CMD6_RE = re.compile(r"^(6) ([\s\S]+)$", re.DOTALL)



CMD7_RE = re.compile(r"^(7) ([^\s][\s\S]*) ([^\s\n]+) ([^\s\n]+)$")


# ---------------------- Helper Functions ---------------------------
def is_Hex_Hash(string: str) -> bool:
    """Check if a string is a valid 64-character hexadecimal hash."""
    HEX_RE = re.compile(r'^[0-9a-fA-F]{64}$')
    return HEX_RE.fullmatch(string) is not None

def strip_proof(proof: str) -> list[tuple[str, str]]:
    """Convert a flat string into list of (direction, hash) tuples."""
    return [(s[0], s[1:]) for s in proof if s]

def to_string(proof: list) -> str:
    """Convert a proof list into a flat space-separated string."""
    return " ".join(d + h for d, h in proof)

def floor_log2(n):
    """Compute floor(log2(n)), adjusted for powers of two."""
    if n & (n - 1) == 0:
        return math.floor(math.log2(n)) - 1
    return math.floor(math.log2(n))

# -------------------- Validation Functions --------------------------
def validate_cmd(cmd: str) -> tuple | None:
    """Validate the command syntax using regex and check argument count."""
    for regex in (TOKEN_RE, CMD6_RE, CMD7_RE):
        match = regex.fullmatch(cmd)
        if match:
            code = int(match.group(1))
            if code == 6:
                parms = [match.group(2)]
            elif code == 7:
                parms = list(match.group(2, 3, 4))
            else:
                parms = cmd.split(" ")[1:]
            required_args = ARG_COUNT[code]
            if code == 4 and len(parms) < required_args:
                return None
            elif code != 4 and len(parms) != required_args:
                return None
            else:
                return code, parms
    return None

def validate_arg_2() -> bool:
    """Check if Merkle tree has at least one leaf."""
    return len(leaf_hashes) > 0

def validate_arg_3(index) -> bool:
    """Check if index is a valid digit and in range of leaves."""
    if not index.isdigit():
        return False
    index = int(index)
    return 0 <= index < len(leaf_hashes)

def validate_arg_4(leaf: str, root: str, *proofs: str) -> bool:
    """Validate Merkle proof format for inclusion check."""
    if not is_Hex_Hash(root):
        return False
    for proof in proofs:
        if proof[0] not in (LEFT, RIGHT) or not is_Hex_Hash(proof[1:]):
            return False
    return True

def validate_arg_6(pem_str: str) -> bool:
    """Check if input is a valid PEM private RSA key."""
    try:
        serialization.load_pem_private_key(
            pem_str.encode(), password=None, backend=default_backend()
        )
        return True
    except Exception:
        return False

def validate_arg_7(pem_str: str, sign: str, message: str) -> bool:
    """Validate public key, signature (base64), and message (hex)."""
    try:
        serialization.load_pem_public_key(pem_str.encode(), backend=default_backend())
        base64.b64decode(sign, validate=True)
        return is_Hex_Hash(message)
    except (ValueError, TypeError):
        return False

VALID = {
    2: lambda args: validate_arg_2(*args),
    3: lambda args: validate_arg_3(*args),
    4: lambda args: validate_arg_4(*args),
    6: lambda args: validate_arg_6(*args),
    7: lambda args: validate_arg_7(*args),
}

def validator(line: str) -> tuple | None:
    """Parse and validate command syntax and arguments."""
    cmd = validate_cmd(line)
    if not cmd:
        return None
    code, args = cmd
    if code in VALID and not VALID[code](args):
        return None
    else:
        return code, args

# ---------------------- Merkle Tree Logic ---------------------------
def add_node(string):
    """Add a new leaf to the Merkle tree by hashing a string."""
    hash_value = hashlib.sha256(string.encode()).digest()
    leaf_hashes.append(hash_value)

def calculate_root(leaf) -> bytes:
    """Recursively compute the Merkle root from a list of leaf hashes."""
    n = len(leaf)
    if n == 1:
        return leaf[0]
    k = 1 << floor_log2(n)
    left = calculate_root(leaf[:k])
    right = calculate_root(leaf[k:])
    combaind=left.hex()+right.hex()
    return hashlib.sha256(combaind.encode()).digest()

def proof_recursive(leaf, index):
    """Recursively construct proof path for a given index."""
    n = len(leaf)
    if n == 1:
        return []
    k = 1 << floor_log2(n)
    if index < k:
        sibling = [(RIGHT, calculate_root(leaf[k:]).hex())]
        subproof = proof_recursive(leaf[:k], index)
        return subproof + sibling
    else:
        sibling = [(LEFT, calculate_root(leaf[:k]).hex())]
        subproof = proof_recursive(leaf[k:], index - k)
        return subproof + sibling

def proof_of_inclusion(index, leaf) -> list[tuple[str, str]]:
    """Construct the full proof of inclusion (including root)."""
    root = calculate_root(leaf).hex()
    if len(leaf) == 1:
        return [("", root)]
    proof = proof_recursive(leaf, int(index))
    return [("", root)] + proof

def verify_proof(*proof: str) -> bool:
    """Verify a Merkle proof for a given leaf and root."""
    leaf_hash = hashlib.sha256(proof[0].encode()).hexdigest()
    root = proof[1]
    for item in proof[2:]:
        direction = item[0]
        hash = item[1:]
        if direction == LEFT:
            leaf_hash = hashlib.sha256((hash + leaf_hash).encode()).hexdigest()
        else:
            leaf_hash = hashlib.sha256((leaf_hash + hash).encode()).hexdigest()
    return leaf_hash==root

def generate_key_pair() -> tuple[str, str]:
    """Generate an RSA key pair and return PEM-encoded strings."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv_pem, pub_pem

def sign(private_key_pem: str) -> str:
    """Sign the Merkle root with a private key and return a base64-encoded signature."""
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        message = calculate_root(leaf_hashes)
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    except Exception:
        return ""

def verify_signature(public_key_pem: str, signature_b64: str, message_hex: str) -> bool:
    """Verify that the given base64 signature matches the message and public key."""
    try:
        signature = base64.b64decode(signature_b64)
        message = bytes.fromhex(message_hex)
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# -------------------------- Command Dispatch -------------------------
COMANDS = {
    1: lambda args: add_node(*args),
    2: lambda args: print(calculate_root(leaf_hashes).hex()),
    3: lambda args: print(to_string(proof_of_inclusion(args[0], leaf_hashes))),
    4: lambda args: print(verify_proof(*args)),
    5: lambda args: print(*generate_key_pair(), sep="\n"),
    6: lambda args: print(sign(*args)),
    7: lambda args: print(verify_signature(*args))
}

# --------------------------- Input Handling --------------------------
def read_input():
    """Read and concatenate multi-line input blocks for commands 6 and 7."""
    try:
        line = input()
    except EOFError:
        return None
    if line.startswith("6"):
        lines = [line]
        while "END RSA PRIVATE KEY" not in lines[-1]:
            try:
                next_line = input()
                lines.append(next_line)
            except EOFError:
                return None
        line = "\n".join(lines)
    elif line.startswith("7"):
        while "END PUBLIC KEY" not in line:
            try:
                next_line = input()
                line += "\n" + next_line
            except EOFError:
                return None
        # Now read the signature and message (they come together in one line)
        try:
            sig_and_msg = input()
            if not sig_and_msg:
                sig_and_msg=input().strip()
            signature, message = sig_and_msg.split(" ", 1)
        except EOFError:
            return None

        line = f"{line} {signature.strip()} {message.strip()}"
    return line

# ---------------------------- Main Loop ------------------------------
def run():
    """Main REPL loop to read, validate, and execute commands."""
    while True:
        try:
            comand = read_input()
            if comand is None:
                break
        except EOFError:
            break
        res = validator(comand)
        if res is None:
            print("")
            continue
        code, args = res
        COMANDS[code](args)

if __name__ == "__main__":
    run()
