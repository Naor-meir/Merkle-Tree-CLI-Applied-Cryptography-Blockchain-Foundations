import unittest
from unittest.mock import patch
import merkle  # ייבוא כללי של הקובץ כמודול
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64, hashlib
from cryptography.hazmat.backends import default_backend

class TestMerkleTree(unittest.TestCase):
    def setUp(self):
        merkle.leaf_hashes.clear()

        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

        self.pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        self.pub_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # Message (hex digest) and valid signature
        self.message = hashlib.sha256(b"example").hexdigest()
        self.signature = base64.b64encode(
            self.private_key.sign(
                bytes.fromhex(self.message),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        ).decode()


    
 



    def tearDown(self):
        pass

# test cases for the validation funcs ------------------------------------------------------------------------
    def test_validate_cmd_valid_commands(self):
        self.assertEqual(merkle.validate_cmd("1 data"), (1, ["data"]))
        self.assertEqual(merkle.validate_cmd("2"), (2, []))
        self.assertEqual(merkle.validate_cmd("3 abcdef"), (3, ["abcdef"]))
        self.assertEqual(merkle.validate_cmd("4 root hash1 hash2"), (4, ["root", "hash1", "hash2"]))
        self.assertEqual(merkle.validate_cmd("4 0 hash1"), (4, ["0", "hash1"]))
        self.assertEqual(merkle.validate_cmd("5"), (5, []))
        self.assertEqual(merkle.validate_cmd("6 signature"), (6, ["signature"]))
        self.assertEqual(merkle.validate_cmd("6 " + self.pem), (6, [self.pem]))
        self.assertEqual(merkle.validate_cmd("7 a b c"), (7, ["a", "b", "c"]))

    def test_validate_cmd_invalid_format(self):
        self.assertIsNone(merkle.validate_cmd(""))  # empty
        self.assertIsNone(merkle.validate_cmd("8 data"))  # invalid code
        self.assertIsNone(merkle.validate_cmd("3"))  # missing arg
        self.assertIsNone(merkle.validate_cmd("1"))  # missing arg
        self.assertIsNone(merkle.validate_cmd("2 extra"))  # too many args
        self.assertIsNone(merkle.validate_cmd("7 a b"))  # too few
        self.assertIsNone(merkle.validate_cmd(" 4 oot"))  # starting space
        self.assertIsNone(merkle.validate_cmd("!"))      # invalid characts
        self.assertIsNone(merkle.validate_cmd("1  data")) # leading space
        self.assertIsNone(merkle.validate_cmd("3ata"))    # missing space
        self.assertIsNone(merkle.validate_cmd("4 root hash1 hash2 extra ")) # trailing space
#------------------- end test if the input is valid ------------------------------------------------------------
#----- start test for the input is valid for spcific functions --------------------------------------------
    def test_validate_arg_2(self):
        # Case: No leaves added to the Merkle tree - > should be return False
        self.assertFalse(merkle.validate_arg_2())

        # Case: One leaf added to the Merkle tree -> should return True
        merkle.leaf_hashes.append(b'\x00' * 32)  # append a dummy hash
        self.assertTrue(merkle.validate_arg_2())
#--------------------func 3 --------------------------------------------------------------------------
    def test_validate_arg_3(self):
        # Setup: Add three dummy leaf hashes
        merkle.leaf_hashes.extend([
            b'\x00' * 32,
            b'\x11' * 32,
            b'\x22' * 32
        ])

        # Valid indexes within bounds
        self.assertTrue(merkle.validate_arg_3("0"))
        self.assertTrue(merkle.validate_arg_3("1"))
        self.assertTrue(merkle.validate_arg_3("2"))

        # Invalid: negative index
        self.assertFalse(merkle.validate_arg_3("-1"))

        # Invalid: index equal to number of leaves
        self.assertFalse(merkle.validate_arg_3("3"))

        # Invalid: non-digit string
        self.assertFalse(merkle.validate_arg_3("a"))

        # Invalid: float string
        self.assertFalse(merkle.validate_arg_3("1.5"))
#--------------------valid func 4------------------------------------------------------------------------
        # ---------- updated tests for validate_arg_4 ----------
    def test_validate_arg_4(self):
        """Unit-tests for validate_arg_4 under the new signature (leaf, root, *proofs)."""

        leaf_a = "leafA"
        leaf_b = "leafB"

        root_hex   = "a" * 64          # valid root (64 hex chars)
        token_left = merkle.LEFT  + "b" * 64
        token_rght = merkle.RIGHT + "c" * 64
        token_bad  = "X" + "d" * 64    # wrong direction

        # --- valid cases ---
        self.assertTrue(merkle.validate_arg_4(leaf_a, root_hex, token_left))
        self.assertTrue(merkle.validate_arg_4(leaf_b, root_hex, token_left, token_rght))

        # --- invalid roots ---
        self.assertFalse(merkle.validate_arg_4(leaf_a, "zz"*32, token_left))   # non-hex
        self.assertFalse(merkle.validate_arg_4(leaf_a, "a"*32,  token_left))   # too short
        self.assertFalse(merkle.validate_arg_4(leaf_a, "a"*65,  token_left))   # too long

        # --- invalid proof tokens ---
        self.assertFalse(merkle.validate_arg_4(leaf_a, root_hex, token_bad))          # bad direction
        self.assertFalse(merkle.validate_arg_4(leaf_a, root_hex, merkle.LEFT+"abc"))  # hash too short
        too_long = "ab"*33
        self.assertFalse(merkle.validate_arg_4(leaf_a, root_hex, merkle.LEFT+too_long))   # hash too long
        self.assertFalse(merkle.validate_arg_4(leaf_a, root_hex, merkle.LEFT+"zz"*32))    # malformed hex

    #-------------------------valid func 6 ----------------------------------------------
    def test_validate_arg_6_valid_pem(self):
        # Valid private key PEM
        self.assertTrue(merkle.validate_arg_6(self.pem))

    def test_validate_arg_6_invalid_content(self):
        # Invalid content inside PEM structure
        invalid_pem = "-----BEGIN PRIVATE KEY-----\ninvalidbase64\n-----END PRIVATE KEY-----"
        self.assertFalse(merkle.validate_arg_6(invalid_pem))

    def test_validate_arg_6_not_a_key(self):
        # Completely malformed string
        self.assertFalse(merkle.validate_arg_6("this is not a key at all"))

    def test_validate_arg_6_missing_begin_line(self):
        # PEM without BEGIN line
        pem_lines = self.pem.splitlines()
        no_begin = "\n".join(pem_lines[1:])
        self.assertFalse(merkle.validate_arg_6(no_begin))

    def test_validate_arg_6_missing_end_line(self):
        # PEM without END line
        pem_lines = self.pem.splitlines()
        no_end = "\n".join(pem_lines[:-1])
        self.assertFalse(merkle.validate_arg_6(no_end))

#-------------------------valid func 7 ----------------------------------------------
    def test_validate_arg_7_valid_input(self):
        # All arguments are valid: public key, base64 signature, hex message
        self.assertTrue(merkle.validate_arg_7(self.pub_pem, self.signature, self.message))

    def test_validate_arg_7_invalid_public_key(self):
        # Public key string is not PEM
        invalid_pem = "not a pem key"
        valid_sig = base64.b64encode(b"sig").decode()
        valid_msg = self.message
        self.assertFalse(merkle.validate_arg_7(invalid_pem, valid_sig, valid_msg))

    def test_validate_arg_7_invalid_signature_base64(self):
        # Signature string is not base64
        invalid_sig = "%%%notbase64$$$"
        valid_msg = self.message
        self.assertFalse(merkle.validate_arg_7(self.pub_pem, invalid_sig, valid_msg))

    def test_validate_arg_7_invalid_message_not_hex(self):
        # Message is not a valid hex string
        invalid_msg = "not_a_hash"
        self.assertFalse(merkle.validate_arg_7(self.pub_pem, self.signature, invalid_msg))

    def test_validate_arg_7_invalid_message_wrong_length(self):
        # Message is a valid hex string, but wrong length (not 64 chars)
        short_hash = "abc123"
        self.assertFalse(merkle.validate_arg_7(self.pub_pem, self.signature, short_hash))

#-------------------------end valid func 7 --------------------------------------------------------------------
#-------------------------test validator func (valid commands) ----------------------------------------------
    def test_validator_valid_command_1(self):
        # Command 1: valid input with one argument
        self.assertEqual(merkle.validator("1 some_data"), (1, ["some_data"]))
    def test_validator_valid_command_2(self):
        # Command 2: valid if leaf_hashes is not empty
        merkle.leaf_hashes.append("leaf1")
        self.assertEqual(merkle.validator("2"), (2, []))
        merkle.leaf_hashes.clear()
    def test_validator_valid_command_3(self):
        # Command 3: valid index within range
        merkle.leaf_hashes.extend(["a", "b", "c"])
        self.assertEqual(merkle.validator("3 1"), (3, ["1"]))
        merkle.leaf_hashes.clear()

    


    def test_validator_valid_command_4(self):
        leaf   = "myLeaf"
        root   = "a" * 64
        proof  = merkle.LEFT + "b" * 64      # 0<b…>

        cmd = f"4 {leaf} {root} {proof}"
        self.assertEqual(
            merkle.validator(cmd),
            (4, [leaf, root, proof])
        )


    def test_validator_valid_command_6(self):

        # Command 6: valid PEM-encoded RSA private key
        self.assertEqual(merkle.validator(f"6 {self.pem}"), (6, [self.pem]))

    def test_validator_valid_command_7(self):
        # Command 7: valid PEM public key, base64 signature, and 64-char hex message
        self.assertEqual(
            merkle.validator(f"7 {self.pub_pem} {self.signature} {self.message}"),
            (7, [self.pub_pem, self.signature, self.message])
        )
#-------------------------test validator func (invalid commands) ----------------------------------------------
    def test_validator_invalid_command_1_missing_arg(self):
        # Command 1: missing argument
        self.assertIsNone(merkle.validator("1"))

    def test_validator_invalid_command_2_empty_leaves(self):
     # Command 2: leaf_hashes is empty
     merkle.leaf_hashes.clear()
     self.assertIsNone(merkle.validator("2"))

    def test_validator_invalid_command_3_out_of_range(self):
        # Command 3: index is out of bounds
        merkle.leaf_hashes.clear()
        merkle.leaf_hashes.append("onlyone")
        self.assertIsNone(merkle.validator("3 5"))

    def test_validator_invalid_command_3_not_digit(self):
        # Command 3: index is not a digit
        self.assertIsNone(merkle.validator("3 not_a_number"))

    def test_validator_invalid_command_4_bad_root(self):
        # Command 4: root is not a valid hex string
     self.assertIsNone(merkle.validator("4 nothex Lbadhash"))

    def test_validator_invalid_command_4_bad_prefix(self):
     # Command 4: direction prefix is invalid
     leaf="data"
     root = "a" * 64
     bad_proof = "X" + "b" * 64
     self.assertIsNone(merkle.validator(f"4 {leaf} {root} {bad_proof}"))

    def test_validator_invalid_command_6_missing_begin_line(self):
     # Command 6: PEM key missing BEGIN line
     pem_lines = self.pem.splitlines()
     no_begin = "\n".join(pem_lines[1:])
     self.assertIsNone(merkle.validator(f"6 {no_begin}"))

    def test_validator_invalid_command_6_missing_end_line(self):
     # Command 6: PEM key missing END line
     pem_lines = self.pem.splitlines()
     no_end = "\n".join(pem_lines[:-1])
     self.assertIsNone(merkle.validator(f"6 {no_end}"))

    def test_validator_invalid_command_7_bad_base64_signature(self):
        # Command 7: signature is not base64
     self.assertIsNone(merkle.validator(f"7 {self.pub_pem} not_base64 {self.message}"))

    def test_validator_invalid_command_7_bad_message(self):
      # Command 7: message is not a valid hex string
      self.assertIsNone(merkle.validator(f"7 {self.pub_pem} {self.signature} not_a_hash"))

    def test_validator_invalid_command_code(self):
     # Command code is not in 1-7
      self.assertIsNone(merkle.validator("8 bad"))
    
         # ------------------- helper functions tests ----------------------------------------------------
#------------------- tests for the helper functions ------------------------------------------------------------
    def test_is_Hex_Hash_valid(self):
        self.assertTrue(merkle.is_Hex_Hash("a" * 64))
        self.assertTrue(merkle.is_Hex_Hash("ABCDEF1234567890abcdef1234567890ABCDEF1234567890abcdef1234567890"))

    def test_is_Hex_Hash_invalid(self):
        self.assertFalse(merkle.is_Hex_Hash("a" * 63))  # too short
        self.assertFalse(merkle.is_Hex_Hash("a" * 65))  # too long
        self.assertFalse(merkle.is_Hex_Hash("g" * 64))  # invalid char
        self.assertFalse(merkle.is_Hex_Hash(""))        # empty

    def test_strip_proof(self):
        proof_input = [merkle.LEFT + "aabbcc", merkle.RIGHT + "112233"]
        expected = [(merkle.LEFT, "aabbcc"), (merkle.RIGHT, "112233")]
        self.assertEqual(merkle.strip_proof(proof_input), expected)

        self.assertEqual(merkle.strip_proof([]), [])
        self.assertEqual(merkle.strip_proof(["", merkle.LEFT + "abcdef"]), [(merkle.LEFT, "abcdef")])

    def test_to_string(self):
        proof_list = [(merkle.LEFT, "aabbcc"), (merkle.RIGHT, "112233")]
        expected = f"{merkle.LEFT}aabbcc {merkle.RIGHT}112233"
        self.assertEqual(merkle.to_string(proof_list), expected)

        self.assertEqual(merkle.to_string([]), "")

    def test_floor_log2(self):
        self.assertEqual(merkle.floor_log2(2), 0)
        self.assertEqual(merkle.floor_log2(4), 1)
        self.assertEqual(merkle.floor_log2(1024), 9)

        self.assertEqual(merkle.floor_log2(3), 1)
        self.assertEqual(merkle.floor_log2(5), 2)
        self.assertEqual(merkle.floor_log2(999), 9)

        with self.assertRaises(ValueError):
            merkle.floor_log2(0)
#-------------------- test for the merkle tree functions ------------------------------------------------------------
    def test_add_node_and_calculate_root(self):
        # Clear leaf_hashes before testing
        merkle.leaf_hashes.clear()

        # Add one node and check the hash is correct
        merkle.add_node("test")
        self.assertEqual(len(merkle.leaf_hashes), 1)
        expected_hash = hashlib.sha256(b"test").digest()
        self.assertEqual(merkle.leaf_hashes[0], expected_hash)

        # Add multiple nodes
        merkle.leaf_hashes.clear()
        data = ["a", "b", "c", "d"]
        for s in data:
            merkle.add_node(s)

        self.assertEqual(len(merkle.leaf_hashes), 4)
        for i, s in enumerate(data):
            self.assertEqual(merkle.leaf_hashes[i], hashlib.sha256(s.encode()).digest())

    def test_calculate_root_single_leaf(self):
        leaf = [hashlib.sha256(b"single").digest()]
        root = merkle.calculate_root(leaf)
        self.assertEqual(root, leaf[0])  # For one leaf, root is the leaf

    def test_calculate_root_multiple_leaves(self):
        # Manually compute root for known 2 leaves
        a_hash=hashlib.sha256(b"a").digest()
        b_hash=hashlib.sha256(b"b").digest()
        a = hashlib.sha256(b"a").hexdigest()
        b = hashlib.sha256(b"b").hexdigest()
        expected_root = hashlib.sha256( (a+b).encode()).digest()
        actual_root = merkle.calculate_root([a_hash,b_hash])
        self.assertEqual(actual_root, expected_root)

        # Check root for 3 leaves: recursive case
        c = hashlib.sha256(b"c").digest()
        root = merkle.calculate_root([a_hash,b_hash,c])
        # Just check output type and length
        self.assertIsInstance(root, bytes)
        self.assertEqual(len(root), 32)
    def test_calculate_root_multiple_leaves_6(self):
        #Test with 6 leaves
        leaves = [hashlib.sha256(f"leaf{i}".encode()).digest() for i in range(6)]
        for i in range(6):
            merkle.add_node(f"leaf{i}")
        h_01= hashlib.sha256( (leaves[0].hex()+leaves[1].hex()).encode()).digest()
        h_23= hashlib.sha256((leaves[2].hex() + leaves[3].hex()).encode()).digest()
        h_45= hashlib.sha256((leaves[4].hex() + leaves[5].hex()).encode()).digest()
        h_0123= hashlib.sha256((h_01.hex() + h_23.hex()).encode()).digest()
        h_012345= hashlib.sha256((h_0123.hex() + h_45.hex()).encode()).digest()
        exected_root = h_012345
        actual_root = merkle.calculate_root(merkle.leaf_hashes)
        self.assertEqual(actual_root, exected_root)
#=================end with adding nodes and calculating root ============================================
    def test_proof_recursive_single_leaf(self):
        merkle.leaf_hashes.clear()
        merkle.add_node("a")
        expected = []  # No siblings in proof
        proof = merkle.proof_recursive(merkle.leaf_hashes, 0)
        self.assertEqual(proof, expected)

    def test_proof_recursive_two_leaves_index_0(self):
        merkle.leaf_hashes.clear()
        merkle.add_node("a")
        merkle.add_node("b")
        expected = [(merkle.RIGHT, merkle.leaf_hashes[1].hex())]
        proof = merkle.proof_recursive(merkle.leaf_hashes, 0)
        self.assertEqual(proof, expected)

    def test_proof_recursive_two_leaves_index_1(self):
        merkle.leaf_hashes.clear()
        merkle.add_node("a")
        merkle.add_node("b")
        expected = [(merkle.LEFT, merkle.leaf_hashes[0].hex())]
        proof = merkle.proof_recursive(merkle.leaf_hashes, 1)
        self.assertEqual(proof, expected)

    def test_proof_recursive_six_leaves_index_1_2_5(self):
        merkle.leaf_hashes.clear()
        for s in ["a", "b", "c", "d", "e", "f"]:
            merkle.add_node(s)
        expected_proofs = {
            1: [
                (merkle.LEFT, merkle.leaf_hashes[0].hex()),
                (
                    merkle.RIGHT,
                    hashlib.sha256(
                        merkle.leaf_hashes[2].hex().encode() + merkle.leaf_hashes[3].hex().encode()
                    ).hexdigest()
                ),
                (
                    merkle.RIGHT,
                    hashlib.sha256(
                        merkle.leaf_hashes[4].hex().encode() + merkle.leaf_hashes[5].hex().encode()
                    ).hexdigest()
                ),
            ],
            2: [
                (merkle.RIGHT, merkle.leaf_hashes[3].hex()),
                (
                    merkle.LEFT,
                    hashlib.sha256(
                        merkle.leaf_hashes[0].hex().encode() + merkle.leaf_hashes[1].hex().encode()
                    ).hexdigest()
                ),
                (
                    merkle.RIGHT,
                    hashlib.sha256(
                        merkle.leaf_hashes[4].hex().encode() + merkle.leaf_hashes[5].hex().encode()
                    ).hexdigest()
                ),
            ],
            5: [
                (merkle.LEFT, merkle.leaf_hashes[4].hex()),
                (
                    merkle.LEFT,
                    hashlib.sha256(
                        hashlib.sha256(
                            merkle.leaf_hashes[0].hex().encode() + merkle.leaf_hashes[1].hex().encode()
                        ).hexdigest().encode() +
                        hashlib.sha256(
                            merkle.leaf_hashes[2].hex().encode() + merkle.leaf_hashes[3].hex().encode()
                        ).hexdigest().encode()
                    ).hexdigest()
                ),
            ],
        }

        for index, expected in expected_proofs.items():
            with self.subTest(index=index):
                proof = merkle.proof_recursive(merkle.leaf_hashes, index)
                self.assertEqual(proof, expected)
#-------------------end test for the proof recursive ------------------------------------------------------------
    def test_proof_of_inclusion_single_leaf(self):
        merkle.leaf_hashes.clear()
        merkle.add_node("a")
        root = merkle.leaf_hashes[0].hex()
        expected = [("", root)]
        proof = merkle.proof_of_inclusion(0, merkle.leaf_hashes)
        self.assertEqual(proof, expected)

    def test_proof_of_inclusion_two_leaves_index_0(self):
        merkle.leaf_hashes.clear()
        merkle.add_node("a")
        merkle.add_node("b")
        root = merkle.calculate_root(merkle.leaf_hashes).hex()
        expected = [("", root), (merkle.RIGHT, merkle.leaf_hashes[1].hex())]
        proof = merkle.proof_of_inclusion(0, merkle.leaf_hashes)
        self.assertEqual(proof, expected)

    def test_proof_of_inclusion_two_leaves_index_1(self):
        merkle.leaf_hashes.clear()
        merkle.add_node("a")
        merkle.add_node("b")
        root = merkle.calculate_root(merkle.leaf_hashes).hex()
        expected = [("", root), (merkle.LEFT, merkle.leaf_hashes[0].hex())]
        proof = merkle.proof_of_inclusion(1, merkle.leaf_hashes)
        self.assertEqual(proof, expected)

    def test_proof_of_inclusion_six_leaves_index_1_2_5(self):
        merkle.leaf_hashes.clear()
        for s in ["a", "b", "c", "d", "e", "f"]:
            merkle.add_node(s)
        root = merkle.calculate_root(merkle.leaf_hashes).hex()
        expected_proofs = {
        1: [
            ("", root),
            (merkle.LEFT, merkle.leaf_hashes[0].hex()),
            (merkle.RIGHT,
            hashlib.sha256(
                (merkle.leaf_hashes[2].hex() + merkle.leaf_hashes[3].hex()).encode()
            ).hexdigest()
            ),
            (merkle.RIGHT,
            hashlib.sha256(
                (merkle.leaf_hashes[4].hex() + merkle.leaf_hashes[5].hex()).encode()
            ).hexdigest()
            )
        ],
        2: [
            ("", root),
            (merkle.RIGHT, merkle.leaf_hashes[3].hex()),
            (merkle.LEFT,
            hashlib.sha256(
                (merkle.leaf_hashes[0].hex() + merkle.leaf_hashes[1].hex()).encode()
            ).hexdigest()
            ),
            (merkle.RIGHT,
            hashlib.sha256(
                (merkle.leaf_hashes[4].hex() + merkle.leaf_hashes[5].hex()).encode()
            ).hexdigest()
            )
        ],
          5: [
            ("", root),
            (merkle.LEFT, merkle.leaf_hashes[4].hex()),
            (merkle.LEFT,
             hashlib.sha256(
                 (
                     hashlib.sha256(
                         (merkle.leaf_hashes[0].hex() + merkle.leaf_hashes[1].hex()).encode()
                     ).hexdigest() +
                     hashlib.sha256(
                         (merkle.leaf_hashes[2].hex() + merkle.leaf_hashes[3].hex()).encode()
                     ).hexdigest()
                 ).encode()
             ).hexdigest()
            )
        ]

    }

        for index, expected in expected_proofs.items():
            with self.subTest(index=index):
                proof = merkle.proof_of_inclusion(index, merkle.leaf_hashes)
                self.assertEqual(proof, expected)
    #-------------------end test for the proof of inclusion ------------------------------------------------------------
    def test_verify_proof_valid_single_leaf(self):
        merkle.leaf_hashes.clear()
        leaf_value = "a"
        merkle.add_node(leaf_value)
        list_proof = merkle.proof_of_inclusion(0, merkle.leaf_hashes)
        proof_string = merkle.to_string(list_proof)
        args=[leaf_value]+ proof_string.split(" ")
        
        self.assertTrue(merkle.verify_proof(*args))

    def test_verify_proof_valid_two_leaves(self):
        merkle.leaf_hashes.clear()
        leaf_values = ["a", "b"]
        for value in leaf_values:
            merkle.add_node(value)
        

        for index in [0, 1]:
            list_proof = merkle.proof_of_inclusion(index, merkle.leaf_hashes)
            proof_string = merkle.to_string(list_proof)
            args= [leaf_values[index]] + proof_string.split(" ")
            with self.subTest(index=index):
                self.assertTrue(merkle.verify_proof(*args))

    def test_verify_proof_valid_six_leaves(self):
        merkle.leaf_hashes.clear()
        leaf_values = ["a", "b", "c", "d", "e", "f"]
        for s in leaf_values:
            merkle.add_node(s)

        for index in [0, 1, 2, 5]:
            list_proof = merkle.proof_of_inclusion(index, merkle.leaf_hashes)
            proof_string = merkle.to_string(list_proof)
            args = [leaf_values[index]] + proof_string.split(" ")
            with self.subTest(index=index):
                self.assertTrue(merkle.verify_proof(*args))

    def test_verify_proof_invalid_modified_hash(self):
        merkle.leaf_hashes.clear()
        leaf_values = ["a", "b"]
        for value in leaf_values:
            merkle.add_node(value)
        list_proof = merkle.proof_of_inclusion(0, merkle.leaf_hashes)
        proof_string = merkle.to_string(list_proof)
        # Modify the proof to make it invalid
        args= [leaf_values[0]] + proof_string.split(" ")
        bad_args= args[:]
        bad_args[1]="a" * 64
        self.assertFalse(merkle.verify_proof(*bad_args))
      

    def test_verify_proof_invalid_fake_proof(self):
        fake_proof_string = ["fake", "a" * 64, merkle.LEFT + "b" * 64]
        self.assertFalse(merkle.verify_proof(*fake_proof_string))

    def test_verify_proof_custom_valid_proof_length_5(self):
    # Step 1: leaf value and hash
        leaf_value = "banana"
        leaf_hash = hashlib.sha256(leaf_value.encode()).digest()

        # Step 2: build proof of depth 5 with dummy hashes
        h1 = hashlib.sha256(b"1").hexdigest()
        h2 = hashlib.sha256(b"2").hexdigest()
        h3 = hashlib.sha256(b"3").hexdigest()
        h4 = hashlib.sha256(b"4").hexdigest()
        h5 = hashlib.sha256(b"5").hexdigest()

        proof = [
            (merkle.LEFT, h1),
            (merkle.RIGHT, h2),
            (merkle.LEFT, h3),
            (merkle.RIGHT, h4),
            (merkle.LEFT, h5),
        ]

        # Step 3: compute expected root using the same hash strategy
        combined = leaf_hash.hex()
        for direction, h in proof:
            if direction == merkle.LEFT:
                combined = hashlib.sha256((h + combined).encode()).hexdigest()
            else:
                combined = hashlib.sha256((combined + h).encode()).hexdigest()
        root = combined

        # Step 4: build full proof list and convert to string
        full_proof = [("", root)] + proof
        proof_string = merkle.to_string(full_proof)

        # Step 5: prepare args for verify_proof (leaf_value + proof parts)
        args = [leaf_value] + proof_string.split()

        self.assertTrue(merkle.verify_proof(*args))

#-------------------end test for the verify proof ------------------------------------------------------------
#==================end with the test for the merkle tree functions ============================================
#===================start with RSA functions tests ============================================================
    def test_generate_key_pair_validity(self):
        priv_pem, pub_pem = merkle.generate_key_pair()

        # Check the output is a tuple of length 2
        self.assertIsInstance((priv_pem, pub_pem), tuple)
        self.assertEqual(len((priv_pem, pub_pem)), 2)

        # Check both are strings
        self.assertIsInstance(priv_pem, str)
        self.assertIsInstance(pub_pem, str)

        # Check that the PEM format starts and ends correctly
        self.assertTrue(priv_pem.startswith("-----BEGIN RSA PRIVATE KEY-----"))
        self.assertTrue(priv_pem.strip().endswith("-----END RSA PRIVATE KEY-----"))

        self.assertTrue(pub_pem.startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(pub_pem.strip().endswith("-----END PUBLIC KEY-----"))

        # Try to load the keys
        private_key = serialization.load_pem_private_key(
            priv_pem.encode(),
            password=None,
            backend=default_backend()
        )
        public_key = serialization.load_pem_public_key(
            pub_pem.encode(),
            backend=default_backend()
        )

        # Check that both keys were successfully loaded
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
#------------------- end tests for generate_key_pair ------------------------------------------------------------
    def test_sign_valid_signature(self):
        merkle.leaf_hashes.clear()
        for s in ["a", "b", "c"]:
            merkle.add_node(s)
        private_key_pem, public_key_pem = merkle.generate_key_pair()
        signature = merkle.sign(private_key_pem)
        self.assertIsInstance(signature, str)
        self.assertTrue(len(signature) > 0)

        root = merkle.calculate_root(merkle.leaf_hashes)
        public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        decoded_signature = base64.b64decode(signature)

        try:
            public_key.verify(
                decoded_signature,
                root,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            verified = True
        except Exception:
            verified = False

        self.assertTrue(verified)
    def test_sign_output_is_base64(self):
        merkle.leaf_hashes.clear()
        for s in ["x", "y", "z"]:
            merkle.add_node(s)
        private_key_pem, _ = merkle.generate_key_pair()
        signature = merkle.sign(private_key_pem)
        try:
            decoded = base64.b64decode(signature, validate=True)
            self.assertIsInstance(decoded, bytes)
        except Exception:
            self.fail("The signature is not a valid base64-encoded string")


    def test_sign_invalid_key(self):
        merkle.leaf_hashes.clear()
        for s in ["a", "b"]:
            merkle.add_node(s)
        invalid_key = "not a valid PEM key"
        signature = merkle.sign(invalid_key)
        self.assertEqual(signature, "")

    def test_sign_with_public_key(self):
        merkle.leaf_hashes.clear()
        for s in ["a", "b", "c"]:
            merkle.add_node(s)
        _, public_key_pem = merkle.generate_key_pair()
        signature = merkle.sign(public_key_pem)  # should fail
        self.assertEqual(signature, "")
#------------------- end tests for sign ------------------------------------------------------------
    def test_verify_signature_valid(self):
        # Generate Merkle root and valid signature
        merkle.leaf_hashes.clear()
        for s in ["a", "b", "c"]:
            merkle.add_node(s)
        priv, pub = merkle.generate_key_pair()
        signature = merkle.sign(priv)
        message_hex = merkle.calculate_root(merkle.leaf_hashes).hex()
        # Should return True for a valid signature
        self.assertTrue(merkle.verify_signature(pub, signature, message_hex))

    def test_verify_signature_invalid_signature(self):
        # Modify one character in the signature
        merkle.leaf_hashes.clear()
        for s in ["a", "b", "c"]:
            merkle.add_node(s)
        priv, pub = merkle.generate_key_pair()
        signature = merkle.sign(priv)
        bad_signature = "A" + signature[1:]  # Corrupt the first character
        message_hex = merkle.calculate_root(merkle.leaf_hashes).hex()
        # Should return False for an invalid signature
        self.assertFalse(merkle.verify_signature(pub, bad_signature, message_hex))

    def test_verify_signature_invalid_message(self):
        # Use an incorrect message
        merkle.leaf_hashes.clear()
        for s in ["a", "b", "c"]:
            merkle.add_node(s)
        priv, pub = merkle.generate_key_pair()
        signature = merkle.sign(priv)
        bad_message = "00" * 32  # Different message (64 hex chars)
        # Should return False for mismatched message
        self.assertFalse(merkle.verify_signature(pub, signature, bad_message))

    def test_verify_signature_invalid_public_key(self):
        # Use a corrupted public key
        merkle.leaf_hashes.clear()
        for s in ["a", "b", "c"]:
            merkle.add_node(s)
        priv, pub = merkle.generate_key_pair()
        signature = merkle.sign(priv)
        message_hex = merkle.calculate_root(merkle.leaf_hashes).hex()
        bad_pub = pub.replace("A", "B", 1)  # Slightly modify PEM
        # Should return False for invalid public key
        self.assertFalse(merkle.verify_signature(bad_pub, signature, message_hex))
#------------------- end tests for verify_signature ------------------------------------------------------------
#============= start with tests for read input and ====================================================
    def test_read_input_commands_1_to_5(self):
     for i in range(1, 6):
          cmd = f"{i} some data"
          with self.subTest(command=i):
             with patch("builtins.input", return_value=cmd):
                   self.assertEqual(merkle.read_input(), cmd)

    def test_read_input_command_6_private_key_minimal(self):
     # יצירת מפתח פרטי מינימלי לדוגמה (כמחרוזת PEM מדומה)
      pem_lines = [
        "6 -----BEGIN RSA PRIVATE KEY-----",
        "MIIEowIBAAKCAQEAu...",
        "U3RlcGhlbiBTYXRvcg==",
        "-----END RSA PRIVATE KEY-----"
    ]

      expected_output = "\n".join(pem_lines)

      with patch("builtins.input", side_effect=pem_lines):
           result = merkle.read_input()
           self.assertEqual(result, expected_output)


    def test_read_input_command_6_private_key(self):
       # Split the PEM into lines, and prefix the first one with '6 '
      pem_lines = self.pem.strip().splitlines()

      input_lines = ["6 " + pem_lines[0]] + pem_lines[1:]

     # Expected output is the full PEM string with newlines
      expected_output = "\n".join(["6 " + pem_lines[0]] + pem_lines[1:])

      with patch("builtins.input", side_effect=input_lines):
             self.assertEqual(merkle.read_input(), expected_output)
    def test_read_input_command_7_public_key_signature_message(self):
        # Prepare the public key split into lines
      pub_lines = self.pub_pem.strip().splitlines()
      sig_and_msg_line = f"{self.signature} {self.message}"
       # Simulate input sequence for command 7: public key, signature, message
      input_lines = ["7 " + pub_lines[0]] + pub_lines[1:] + [sig_and_msg_line]
    



     # The expected output includes newlines between public key lines,
      # followed by space-separated signature and message
      expected_output = "\n".join(["7 " + pub_lines[0]] + pub_lines[1:]) + f" {self.signature} {self.message}"

    
    

      with patch("builtins.input", side_effect=input_lines):
          result = merkle.read_input()
          self.assertEqual(result, expected_output)
#------------------------------ end tests for read_input func - ---------------------------
#===============================start tests for the run func -  E2E tests ================================
    def test_run_full_cli_flow(self):
        """
        CLI end-to-end test that follows the precise input / output order
        requested by the user.
        """

        # --- offline computations on a local ABC tree (no global side-effects) ---
        leaf_a = hashlib.sha256(b"a").digest()
        root1_hex = leaf_a.hex()

        leaf_b = hashlib.sha256(b"b").digest()
        root2_hex = hashlib.sha256(
    (leaf_a.hex() + leaf_b.hex()).encode()
).hexdigest()


        leaf_c = hashlib.sha256(b"c").digest()
        leaves_abc = [leaf_a, leaf_b, leaf_c]

        # full proofs (they already include ("", root) as first pair)
        proof_a_str = " ".join(d + h for d, h in merkle.proof_of_inclusion(0, leaves_abc))
        proof_c_str = " ".join(d + h for d, h in merkle.proof_of_inclusion(2, leaves_abc))

        # --- input sequence exactly as required ---
        inputs = [
            "2",                # empty tree          → ""
            "1 a", "2",         # root1
            "1 b", "2",         # root2
            "1 c",
            "3 0",              # proof-a
            "3 2",              # proof-c
            f"4 a {proof_a_str}",
            f"4 c {proof_c_str}",
            f"4 b {proof_a_str}",   # wrong proof for b
            "9",
            "1  d",             # two spaces after 1
            "1",
            "2 R",
            "3 5",
            "4 c",
        ]

        with patch("builtins.input", side_effect=inputs + [EOFError()]), \
             patch("builtins.print") as mp:
            merkle.run()

        printed = [c.args[0] for c in mp.call_args_list if c.args]

        # --- expected order -------------------------------------------------------
        # 0
        self.assertEqual(printed[0], "")                 # first '2' on empty tree
        # 1–2
        self.assertEqual(printed[1], root1_hex)          # root after [a]
        self.assertEqual(printed[2], root2_hex)          # root after [a,b]
        # 3–4 proofs
        self.assertEqual(printed[3], proof_a_str)
        self.assertEqual(printed[4], proof_c_str)
        # 5–7 verification results
        self.assertIs(printed[5], True)    # first verification – True
        self.assertIs(printed[6], True)    # second verification – True
        self.assertIs(printed[7], False)   # wrong proof – False
        # 8-13 : exactly six empty lines for the six invalid commands
        self.assertTrue(all(line == "" for line in printed[8:]))
        self.assertEqual(len(printed[8:]), 6)

    def test_run_keygen_sign_verify_flow(self):
        """End-to-end: add leaf, print root, sign & verify with our own keys."""
        # ----- offline: compute root & signature without touching global state
        leaf_val = "a"
        root_hex  = hashlib.sha256(leaf_val.encode()).hexdigest()   # root of single leaf

        priv_pem, pub_pem = merkle.generate_key_pair()
        # sign locally
        private_key = serialization.load_pem_private_key(priv_pem.encode(), None)
        signature_b64 = base64.b64encode(
            private_key.sign(
                bytes.fromhex(root_hex),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        ).decode()

        # split PEM lines for commands 6 / 7
        priv_lines = priv_pem.strip().splitlines()
        pub_lines  = pub_pem.strip().splitlines()

        # ----- CLI input sequence -----
        inputs = [
            "1 a",
            "2",                        # should print root_hex
            "5",                        # CLI generates its own keys (ignored)
            # cmd-6: our private key
            "6 " + priv_lines[0], *priv_lines[1:],
            # cmd-7: our public key, signature, root
            "7 " + pub_lines[0], *pub_lines[1:], f"{signature_b64} {root_hex}"

        ]

        merkle.leaf_hashes.clear()      # ensure tree empty before run()
        with patch("builtins.input", side_effect=inputs + [EOFError()]), \
            patch("builtins.print") as mp:
            merkle.run()

        printed = [str(c.args[0]) for c in mp.call_args_list if c.args]

        # assertions
        self.assertIn(root_hex, printed)         # root printed by cmd-2
        # self.assertIn(signature_b64, printed)    # signature printed by cmd-6
        self.assertEqual(printed[-1], "True")    # verification success
# ------------------------------------------------------------
    # 2. cmd-6 with an invalid private-key string  → empty line
    # ------------------------------------------------------------
    def test_run_cmd6_invalid_private_key(self):
       """
     Command-6 with an invalid private key:
      – Provide a syntactically correct PEM block (BEGIN … END)
         but with non-base64 garbage in the body.
       – validator should reject it ⇒ run() prints an empty line ("").
       """
       invalid_pem = [
          "6 -----BEGIN RSA PRIVATE KEY-----",
         "not_base64!",                    # corrupted payload
         "-----END RSA PRIVATE KEY-----"
     ]
       inputs = ["1 a", "2", *invalid_pem]

       with patch("builtins.input", side_effect=inputs + [EOFError()]), \
          patch("builtins.print") as mp:
             merkle.run()

             printed = [c.args[0] for c in mp.call_args_list if c.args]

       # The invalid cmd-6 must result in at least one empty line.
             self.assertIn("", printed)
#------------------------------------------------------------------------------------------------------------------------------
    # ------------------------------------------------------------
    # 3. cmd-7 syntactically INVALID (pubkey / signature / message)
    #    → each invocation should print an empty line
    # ------------------------------------------------------------
    def test_run_cmd7_syntactically_invalid(self):
        # Build a single-leaf tree so that we have a known root
        merkle.leaf_hashes.clear()
        merkle.add_node("x")
        root_hex = merkle.calculate_root(merkle.leaf_hashes).hex()

        # Generate a valid key pair and signature (to use in valid positions)
        priv_ok, pub_ok = merkle.generate_key_pair()
        sig_ok = merkle.sign(priv_ok)
        pub_ok_lines = pub_ok.strip().splitlines()

        # Each sublist represents one invalid cmd-7 sequence of exactly three lines:
        #   1) a malformed Public Key (correct BEGIN/END but garbage inside),
        #   2) a malformed Base64 signature,
        #   3) a malformed message (not 64-hex).
        invalid_cases = [
            [
                "7 -----BEGIN PUBLIC KEY-----",
                "invalid-public-key-content",
                "-----END PUBLIC KEY-----",
                f"{sig_ok} {root_hex}"  # ✅ תקין מבחינת פורמט
            ],
            [
                "7 " + pub_ok_lines[0], *pub_ok_lines[1:],
                f"%%%notbase64%%% {root_hex}"  # ✅ חתימה לא תקינה, אבל יש רווח
            ],
            [
                "7 " + pub_ok_lines[0], *pub_ok_lines[1:],
                f"{sig_ok} not_a_hash"  # ✅ הודעה לא תקינה, אבל עם רווח
            ],
        ]


        # Flatten the list of invalid cases into a single list of input lines,
        # preceded by "1 x" so the tree is non-empty.
        inputs = ["1 x"] + [line for case in invalid_cases for line in case]

        with patch("builtins.input", side_effect=inputs + [EOFError()]), \
             patch("builtins.print") as mp:
            merkle.run()

        # Collect all printed outputs
        printed = [c.args[0] for c in mp.call_args_list if c.args]

        # Expect at least three empty lines (one for each invalid cmd-7)
        self.assertGreaterEqual(printed.count(""), 3)


 # ------------------------------------------------------------
    # 4. cmd-7 syntactically VALID but should verify to False
    #    (wrong pubkey / wrong signature / wrong message)
    # ------------------------------------------------------------
    def test_run_cmd7_verification_false(self):
        # build single-leaf tree
        merkle.leaf_hashes.clear()
        merkle.add_node("y")
        root_hex = merkle.calculate_root(merkle.leaf_hashes).hex()

        # key-pair #1 (used for good signature)
        priv1, pub1 = merkle.generate_key_pair()
        sig1 = merkle.sign(priv1)               # valid signature for root_hex

        # another key-pair for wrong-pubkey case
        _,     pub2 = merkle.generate_key_pair()

        # mutate signature (1st char) – still base64 but invalid
        sig_bad = ("A" if sig1[0] != "A" else "B") + sig1[1:]

        wrong_msg = "00" * 32                   # 64-hex but not the real root

        pub1_lines = pub1.strip().splitlines()
        pub2_lines = pub2.strip().splitlines()

        inputs = [
            # A. wrong public key
            "7 " + pub2_lines[0], *pub2_lines[1:], f"{sig1} {root_hex}",

            # B. wrong signature
            "7 " + pub1_lines[0], *pub1_lines[1:], f"{sig_bad} {root_hex}",

            # C. wrong message
            "7 " + pub1_lines[0], *pub1_lines[1:], f"{sig1} {wrong_msg}",
        ]


        with patch("builtins.input", side_effect=inputs + [EOFError()]), \
             patch("builtins.print") as mp:
            merkle.run()

        printed = [str(c.args[0]) for c in mp.call_args_list if c.args]
        # three cmd-7 calls → all must output False
        self.assertGreaterEqual(printed.count("False"), 3)

if __name__ == "__main__":
    unittest.main()