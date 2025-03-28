/*
 * ilpyo hong, D24130377
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
#define BLOCK_SIZE 16
extern unsigned char sbox[16][16];
extern unsigned char inv_sbox[16][16];
extern unsigned char r_con[11];
/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

#endif
