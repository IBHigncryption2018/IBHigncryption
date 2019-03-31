#ifndef _KEM_API_H
#define _KEM_API_H
#ifdef __cplusplus
extern "C" {
#endif

#include "cipher.h"
#include "ibh.h"
#include "secret_key.h"
#include "plaint.h"
#include "rand.h"
#include "util.h"
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct kem_context_s {
  pairing_t pairing;
  element_t mk;
} kem_context_t;

// G1、G2、GT群中的大整数转化为字符串后的长度，比如用于验证的X
#define ELE_LEN 128

// Zr群的大整数转化为字符串后的长度，比如主密钥s
#define ZrLEN 20

//可允许的最大字符串长度
#define MAX_LEN 1024

//用于加密的密钥长度
#define M_LEN 32

// AES加密后的密文C
#define C_LEN 96

//私钥sk的长度，包括发送私钥和接收私钥
#define KEM_SECRETKEYBYTES 2 * ELE_LEN
//公钥长度
#define KEM_PUBLICKEYBYTES ELE_LEN
//传输的共享秘密长度，包括明文密钥和发送者ID
#define KEM_BYTES M_LEN+KEM_PUBLICKEYBYTES

//传输的密文长度，包括用于验证的X和AES加密后的密文C
#define KEM_CIPHERTEXTBYTES C_LEN + ELE_LEN
//算法名称
#define SIG_ALGNAME “IBHigncryption”

int kem_init(char *file);

int kem_keygen(unsigned char *pk, unsigned char *sk);

int kem_enc(unsigned char *pk, unsigned char *ss, unsigned char *sk,
            unsigned char *ct);

int kem_dec(unsigned char *sk, unsigned char *ct, unsigned char *pk,
            unsigned char *ss);

int kem_init1(char *file);

int kem_keygen1(unsigned char *pk, unsigned char *sk);

int kem_enc1(unsigned char *pk, unsigned char *ss, unsigned char *sk,
             unsigned char *ct);

int kem_dec1(unsigned char *sk, unsigned char *ct, unsigned char *pk,
             unsigned char *ss);

#ifdef __cplusplus
}
#endif
#endif // KEM_API_H
