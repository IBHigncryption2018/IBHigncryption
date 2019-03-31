#include "kem_api.h"
#include "cipher.h"
#include "ibh.h"
#include "secret_key.h"
#include "plaint.h"
#include "str.h"
#include "util.h"

static kem_context_t *kem_ctx = NULL;

/*
        密钥环境初始化
*/
int kem_init(char *file) {
  char s[16384];
  FILE *fp = NULL;
  if (kem_ctx == NULL) {
    fp = fopen(file, "r");
    if (!fp) {
      pbc_die("error opening %s", file);
    }
    size_t count = fread(s, 1, 16384, fp);
    if (!count) {
      pbc_die("input error");
    }
    fclose(fp);
    kem_ctx = malloc(sizeof(kem_context_t));
    if (!kem_ctx) {
      return -1;
    }
    if (pairing_init_set_buf(kem_ctx->pairing, s, count)) {
      pbc_die("pairing init failed");
    }
    element_init_Zr(kem_ctx->mk, kem_ctx->pairing);
    /* 随机生成主密钥  */
    element_random(kem_ctx->mk);
  }
  return 0;
}

/*
        根据公钥生成私解对
*/
int kem_keygen(unsigned char *pk, unsigned char *sk) {
  element_t h1, h2, SK1, SK2;
  secret_key *key;
  key = (secret_key *)sk;

  if (key == NULL) {
    key = secret_key_create();
  }

  if (key == NULL) {
    pbc_die("malloc error");
  }

  element_init_G1(h1, kem_ctx->pairing);
  element_init_G1(SK1, kem_ctx->pairing);
  element_init_G2(h2, kem_ctx->pairing);
  element_init_G2(SK2, kem_ctx->pairing);
  // x_to_ele(s, kem_ctx->mk);
  unsigned char *shash1, *shash2;
  shash1 = md5_16(pk);
  // h=h(ID)
  element_from_hash(h1, shash1, AES_BLOCK_SIZE);
  // sk=h^s
  // element_pow_zn(SK1, h1, s);
  element_pow_zn(SK1, h1, kem_ctx->mk);
  shash2 = sha1(pk);
  // h=h(ID)
  element_from_hash(h2, shash2, AES_BLOCK_SIZE);
  // sk=h^s
  // element_pow_zn(SK2, h2, s);
  element_pow_zn(SK2, h2, kem_ctx->mk);
  free(shash1);
  shash1 = NULL;
  free(shash2);
  shash2 = NULL;

  secret_key_set0(key, element_length_in_bytes(SK1), NULL);
  element_to_bytes(secret_key_get0(key), SK1);

  secret_key_set1(key, element_length_in_bytes(SK2), NULL);
  element_to_bytes(secret_key_get1(key), SK2);

  element_clear(SK1);
  element_clear(SK2);
  element_clear(h1);
  element_clear(h2);
  return 0;
}

/**
 * 加密函数
 * pk 对方的公钥
 * plaint_ss 共享秘密
 * sk 自己的私钥
 * ciphertext 共享秘密密文
 * 返回值: 成功返回0，失败返回-1
 */
int kem_enc(unsigned char *pk, unsigned char *s, unsigned char *sk,
            unsigned char *c) {
  struct Plaintext_s *plaint_ss = (struct Plaintext_s *)s;
  struct ciphertext_s *ciphertext = (struct ciphertext_s *)c;
  struct str_s *plain = NULL;
  unsigned char *key = NULL;
  unsigned char *shash = NULL;
  AES_KEY K1;
  int ret = -1 ;
  element_t ska1;
  element_t x, tem, PS, ha1, hb2, X;
  element_t ele_unit;

  if (!plaint_ss->ID || str_length(plaint_ss->ID) <= 0) {
    printf("error input  \n");
    return -1;
  }
  if (!plaint_ss->M || str_length(plaint_ss->M) <= 0) {
    printf("error input  \n");
    return -1;
  }
  element_init_G1(ska1, kem_ctx->pairing);
  element_init_G1(X, kem_ctx->pairing);
  element_init_G1(ha1, kem_ctx->pairing);
  element_init_G2(hb2, kem_ctx->pairing);
  element_init_GT(tem, kem_ctx->pairing);
  element_init_GT(PS, kem_ctx->pairing);
  element_init_Zr(x, kem_ctx->pairing);
  element_init_GT(ele_unit, kem_ctx->pairing);

  element_from_bytes(ska1, sk);

  shash = md5_16(str_get(plaint_ss->ID));
  element_from_hash(ha1, shash, AES_BLOCK_SIZE);
  free(shash);
  shash = NULL;

  shash = sha1(pk);
  // hb=h(IDb)
  element_from_hash(hb2, shash, AES_BLOCK_SIZE);
  element_random(x);
  // X=ha^x
  element_pow_zn(X, ha1, x);
  //生成证书
  if (!ciphertext->cert) {
    ciphertext->cert = str_create();
  }
  str_set(ciphertext->cert, element_length_in_bytes(X), NULL);
  ciphertext->cert->length = element_to_bytes(str_get(ciphertext->cert), X);
  // tem=e(SKa,hb)
  pairing_apply(tem, ska1, hb2, kem_ctx->pairing);
  // PS=tem^x
  element_pow_zn(PS, tem, x);

  //判断PS是否是单位元
  element_set1(ele_unit);
  if (!element_cmp(ele_unit, PS)) {
    printf("加密过程得到了不符合规范的双线性对结果！\n");
    goto END;
  }

  key = KDF(PS, X, pk);
  AES_set_encrypt_key(key, AES_BLOCK_SIZE * 8, &K1); // key
  //组织数据 自己的公钥+明文
  plain = PlainTXT(plaint_ss, x);
  //加密生成密文
  if (!ciphertext->CT) {
    ciphertext->CT = str_create();
  }
  str_set(ciphertext->CT, (str_length(plain) + AES_BLOCK_SIZE), NULL);
  ciphertext->CT->length = ecb_encrypt(str_get(plain), str_get(ciphertext->CT),
                                       str_length(plain), &K1);
  ret = 0 ;

  str_release(plain);
  plain = NULL;
  free(key);
  free(shash);
END:
  shash = NULL;
  key = NULL;

  element_clear(ska1);
  element_clear(x);
  element_clear(tem);
  element_clear(PS);
  element_clear(ha1);
  element_clear(hb2);
  element_clear(X);
  element_clear(ele_unit);
  return ret;
}

/**
 * 解密函数
 * sk 自己的私钥2
 * ciphertext 共享秘密密文
 * pk 密钥信息
 * plaint_ss 共享秘密明文
 * 返回值: 成功返回0，失败返回-1
 */
int kem_dec(unsigned char *sk, unsigned char *c, unsigned char *pk,
            unsigned char *s) {
  int Mlen;
  int IDlen = KEM_PUBLICKEYBYTES;
  struct Plaintext_s *plaint_ss = NULL;
  struct ciphertext_s *ciphertext = NULL;
  unsigned char *shash = NULL;
  unsigned char *key = NULL;
  struct str_s *decrypt_result = NULL;
  int ret = -1;
  element_t SKb2;
  element_t tem, ha1;
  element_t x, PS, X;
  element_t ele_unit;

  plaint_ss = (struct Plaintext_s *)s;
  ciphertext = (struct ciphertext_s *)c;

  element_init_G2(SKb2, kem_ctx->pairing);
  element_init_G1(tem, kem_ctx->pairing);
  element_init_G1(ha1, kem_ctx->pairing);
  element_init_G1(X, kem_ctx->pairing);
  element_init_GT(PS, kem_ctx->pairing);
  element_init_Zr(x, kem_ctx->pairing);
  element_init_GT(ele_unit, kem_ctx->pairing);

  element_from_bytes(SKb2, sk);
  //证书转换
  element_from_bytes(X, str_get(ciphertext->cert));
  AES_KEY de_key;

  decrypt_result = str_create();
  str_set(decrypt_result,
          str_length(ciphertext->CT) + KEM_PUBLICKEYBYTES + 2 * ZrLEN, NULL);

  // PS=e(X,skb)
  pairing_apply(PS, X, SKb2, kem_ctx->pairing);
  //判断PS是否是单位元
  element_set1(ele_unit);
  if (!element_cmp(ele_unit, PS)) {
    printf("解密过程得到了不符合规范的双线性对结果！\n");
    goto END;
  }
  key = KDF(PS, X, pk);

  AES_set_decrypt_key(key, AES_BLOCK_SIZE * 8, &de_key);

  Mlen = ecb_decrypt(str_get(ciphertext->CT), str_get(decrypt_result),
                     str_length(ciphertext->CT), &de_key);

  if (get_info(x, plaint_ss, str_get(decrypt_result), IDlen, Mlen) != 0) {
    printf("数据校验失败  \n");
    goto END;
  }
  shash = md5_16(str_get(plaint_ss->ID));
  // ha=h(IDa)
  element_from_hash(ha1, shash, AES_BLOCK_SIZE);
  // tem=ha^x
  element_pow_zn(tem, ha1, x);
  //验证x属于Zr且X=h^x
  if (!element_cmp(tem, X) && kem_ctx->pairing->Zr == x->field) {
    ret = 0;
  } else {
    printf("校验失败 \n");
  }

END:
  str_release(decrypt_result);
  decrypt_result = NULL;
  if (shash) {
    free(shash);
    shash = NULL;
  }
  if (key) {
    free(key);
    key = NULL;
  }
  element_clear(tem);
  element_clear(ha1);
  element_clear(x);
  element_clear(PS);
  element_clear(X);
  element_clear(SKb2);
  element_clear(ele_unit);
  // printf("校验成功 %d \n", ret) ;
  return ret;
}
