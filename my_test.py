import ctypes
import os
import sys
import random
import copy
import unittest

sys.path.append(os.path.join(os.path.dirname(__file__), "./external/python-aes"))
from aes import sub_bytes, shift_rows, bytes2matrix, matrix2bytes



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

            # Python function
            matrix = bytes2matrix(block)
            sub_bytes(matrix)
            py_result = matrix2bytes(matrix)

            # C function
            c_block = to_c_block(block)
            lib.sub_bytes(c_block)
            c_result = bytes(c_block)
            c_result_matrix = bytes2matrix(c_result)

            self.assertEqual(py_result, c_result, f"original : {matrix} -> result : {c_result_matrix} SubBytes mismatch between C and Python")

    def test_shift_rows_equivalent(self):
        for _ in range(3):
            block = random_block()
            
            # Python function
            matrix = bytes2matrix(block)
            shift_rows(matrix)
            py_result = matrix2bytes(matrix)

            # C function
            c_block = to_c_block(block)
            lib.shift_rows(c_block)
            c_result = bytes(c_block)
            c_result_matrix = bytes2matrix(c_result)


            self.assertEqual(py_result, c_result, f"original : {matrix} -> result : {c_result_matrix} ShiftRows mismatch between C and Python")

if __name__ == '__main__':
    unittest.main()