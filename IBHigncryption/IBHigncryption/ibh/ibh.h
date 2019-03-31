#ifndef IBH_H
#define IBH_H
#ifdef __cplusplus
extern "C" {
#endif

#include "kem_api.h"
#include "pbc/pbc.h"
#include "plaint.h"
#include "secret_key.h"
#include "cipher.h"
#include "rand.h"
#include "util.h"
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <pbc/pbc.h>

unsigned char *md5_16(unsigned char *data);

unsigned char *sha1(unsigned char *data);


unsigned char *KDF(element_t PS, element_t X, unsigned char *IDb);

struct str_s *PlainTXT(struct Plaintext_s *p, element_t x);

int ecb_encrypt(unsigned char *in, unsigned char *out, size_t len,
                const AES_KEY *key);
int ecb_decrypt(unsigned char *in, unsigned char *out, size_t len,
                const AES_KEY *key);
int get_info(element_t x, struct Plaintext_s *p, unsigned char *data,
             int ID_len, int data_len);

#ifdef __cplusplus
}
#endif
#endif
