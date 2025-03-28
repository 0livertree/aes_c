import ctypes
import os
import sys
import random
import copy
import unittest

sys.path.append(os.path.join(os.path.dirname(__file__), "./external/python-aes"))
from aes import sub_bytes, shift_rows, mix_columns, bytes2matrix, matrix2bytes, inv_sub_bytes, inv_shift_rows, inv_mix_columns, AES, add_round_key


if os.name == 'nt':
    lib = ctypes.CDLL("./rijndael.dll")
else:
    lib = ctypes.CDLL("./rijndael.so")


lib.sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
lib.sub_bytes.restype = None

lib.shift_rows.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
lib.shift_rows.restype = None

lib.mix_columns.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
lib.mix_columns.restype = None

lib.invert_sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
lib.invert_sub_bytes.restype = None

lib.invert_shift_rows.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
lib.invert_shift_rows.restype = None

lib.invert_mix_columns.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
lib.invert_mix_columns.restype = None

lib.add_round_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
lib.add_round_key.restype = None

lib.expand_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
lib.expand_key.restype = ctypes.POINTER(ctypes.c_ubyte)

lib.aes_encrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
lib.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

lib.aes_decrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
lib.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)


# Create Block & Transform bytes
def random_block():
    return bytes(random.randint(0, 255) for _ in range(16))

def to_c_block(py_bytes):
    return (ctypes.c_ubyte * 16)(*py_bytes)




class TestAESFunctions(unittest.TestCase):

    def test_sub_bytes_equivalent(self):
        for _ in range(3):
            block = random_block()

            origin = bytes2matrix(block)
            # Python function
            matrix = bytes2matrix(block)
            sub_bytes(matrix)
            py_result = matrix2bytes(matrix)

            # C function
            c_block = to_c_block(block)
            lib.sub_bytes(c_block)
            c_result = bytes(c_block)
            c_result_matrix = bytes2matrix(c_result)

            self.assertEqual(py_result, c_result, f"original : {origin} -> result : {c_result_matrix} -> py_result : {matrix} SubBytes mismatch between C and Python")

    def test_shift_rows_equivalent(self):
        for _ in range(3):
            block = random_block()
            origin = bytes2matrix(block)
            # Python function
            matrix = bytes2matrix(block)
            shift_rows(matrix)
            py_result = matrix2bytes(matrix)

            # C function
            c_block = to_c_block(block)
            lib.shift_rows(c_block)
            c_result = bytes(c_block)
            c_result_matrix = bytes2matrix(c_result)

            self.assertEqual(py_result, c_result, f"original : {origin} -> c_result : {c_result_matrix} -> py_result : {matrix} ShiftRows mismatch between C and Python")

    def test_invert_shift_rows_equivalent(self):
        for _ in range(3):
            block = random_block()
            
            origin = bytes2matrix(block)
            # Python function
            matrix = bytes2matrix(block)
            inv_shift_rows(matrix)
            py_result = matrix2bytes(matrix)

            # C function
            c_block = to_c_block(block)
            lib.invert_shift_rows(c_block)
            c_result = bytes(c_block)
            c_result_matrix = bytes2matrix(c_result)

            self.assertEqual(py_result, c_result, f"original : {origin} -> c_result : {c_result_matrix} -> py_result : {matrix} invert_ShiftRows mismatch between C and Python")

    def test_invert_sub_bytes_equivalent(self):
        for _ in range(3):
            block = random_block()
            
            origin = bytes2matrix(block)
            # Python function
            matrix = bytes2matrix(block)
            inv_sub_bytes(matrix)
            py_result = matrix2bytes(matrix)

            # C function
            c_block = to_c_block(block)
            lib.invert_sub_bytes(c_block)
            c_result = bytes(c_block)
            c_result_matrix = bytes2matrix(c_result)

            self.assertEqual(py_result, c_result, f"original : {origin} -> c_result : {c_result_matrix} -> py_result : {matrix} ShiftRows mismatch between C and Python")
    
    def test_add_round_key_equivalent(self):
        for _ in range(3):
            block = random_block()
            key = random_block()

            origin = bytes2matrix(block)
            #Python function
            matrix = bytes2matrix(block)
            key_matrix = bytes2matrix(key)
            add_round_key(matrix, key_matrix)
            py_result = matrix2bytes(matrix)

            # C function
            c_block = to_c_block(block)
            c_key = to_c_block(key)
            lib.add_round_key(c_block, c_key)
            c_result = bytes(c_block)
            c_result_matrix = bytes2matrix(c_result)

            self.assertEqual(py_result, c_result, f"original : {origin}, key : {key_matrix} -> c_result : {c_result_matrix} -> py_result : {py_result} add_round_key mismatch between C and Python")


    def test_mix_columns_equivalent(self):
        for _ in range(3):
            block = random_block()
            
            origin = bytes2matrix(block)
            # Python function
            matrix = bytes2matrix(block)
            mix_columns(matrix)
            py_result = matrix2bytes(matrix)

            # C function
            c_block = to_c_block(block)
            lib.mix_columns(c_block)
            c_result = bytes(c_block)
            c_result_matrix = bytes2matrix(c_result)

            self.assertEqual(py_result, c_result, f"original : {origin} -> c_result : {c_result_matrix} -> py_result : {matrix} mixColumn mismatch between C and Python")


    def test_invert_mix_columns_equivalent(self):
        for _ in range(3):
            block = random_block()

            
            origin = bytes2matrix(block)
            # Python function
            matrix = bytes2matrix(block)
            inv_mix_columns(matrix)
            py_result = matrix2bytes(matrix)

            # C function
            c_block = to_c_block(block)
            lib.invert_mix_columns(c_block)
            c_result = bytes(c_block)
            c_result_matrix = bytes2matrix(c_result)

            self.assertEqual(py_result, c_result, f"original : {origin} -> c_result : {c_result_matrix} -> py_result : {matrix} invert_mixColumns mismatch between C and Python")

    def test_expand_key_equivalend(self):
        for _ in range(3):
            key = random_block()
            # Python AES class init

            test_aes = AES(key)
            int_matrix = [[list(cell) if isinstance(cell, bytes) else cell for cell in row] for row in test_aes._key_matrices]
            # C function
            key_array = to_c_block(key)
            result_ptr = lib.expand_key(key_array)
            c_expanded_key_bytes = bytes(result_ptr[i] for i in range(176))

            c_result = [[list(c_expanded_key_bytes[i + j:i + j + 4]) for j in range(0, 16, 4)] for i in range(0, 176, 16) ]

            self.assertEqual(int_matrix, c_result, f"key : {key} -> c_result : {c_result} -> py_result : {int_matrix} key_matrices mismatch between C and Python")

class FullAEStest(unittest.TestCase):
    def test_encryption_single_block(self):
        for _ in range(3):
            key = random_block()
            aes = AES(key)
            plaintext = random_block()

            python_ciphertext = aes.encrypt_block(plaintext)

            key_array = to_c_block(key)
            plaintext_array = to_c_block(plaintext)
            c_ciphertext = lib.aes_encrypt_block(plaintext_array, key_array)
            c_cipher_byte = bytes(c_ciphertext[i] for i in range(16))

            self.assertEqual(python_ciphertext, c_cipher_byte, f"key : {key} -> c_result : {c_cipher_byte} -> py_result : {python_ciphertext} encryption mismatch between C and Python")


    def test_decryption_single_block(self):
        for _ in range(3):
            key = random_block()
            aes = AES(key)
            ciphertext = random_block()

            python_plaintext = aes.decrypt_block(ciphertext)

            key_array = to_c_block(key)
            ciphertext_array = to_c_block(ciphertext)
            c_plaintext = lib.aes_decrypt_block(ciphertext_array, key_array)
            c_plain_byte = bytes(c_plaintext[i] for i in range(16))

            self.assertEqual(python_plaintext, c_plain_byte, f"key : {key} -> c_result : {c_plain_byte} -> py_result : {python_plaintext} decryption mismatch between C and Python")



if __name__ == '__main__':
    unittest.main()
