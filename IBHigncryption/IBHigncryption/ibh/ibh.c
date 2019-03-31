#include "ibh.h"

/*
 *将解密得来的字符串，取出x,IDa,M;ID_len为ID长度
 */
int get_info(element_t x, struct Plaintext_s *p, unsigned char *data,
             int ID_len, int data_len) {
  unsigned char tem[1024];
  memset((char *)tem, 0, 1024);
  int i;
  int offset = 2 * ZrLEN;
  for (i = 0; i < offset; i++) {
    tem[i] = data[i];
  }
  tem[i] = '\0';
  x_to_ele(x, tem); // x
  if (!p->ID) {
    p->ID = str_create();
  }
  if (!p->M) {
    p->M = str_create();
  }
  if (data_len > ID_len) {
    str_set(p->ID, ID_len, data + data_len - ID_len);
    if (data_len > ID_len + offset) {
      str_set(p->M, data_len - ID_len - offset, data + offset);
      return 0;
    }
  }
  return -1;
}

/**
 * ECB模式的AES加密
 */
int ecb_encrypt(unsigned char *in, unsigned char *out, size_t len,
                const AES_KEY *key) {
  //对齐分组
  int length = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
  int count = 0;
  while (count < length) {
    AES_encrypt(in + count, out + count, key);
    count += AES_BLOCK_SIZE;
  }
  return count;
}

/**
 * ECB模式的AES解密
 */
int ecb_decrypt(unsigned char *in, unsigned char *out, size_t len,
                const AES_KEY *key) {
  int count = 0;
  while (count < len) {
    AES_decrypt(in + count, out + count, key);
    count += AES_BLOCK_SIZE;
  }
  return strlen((char *)out);
}

/*
 *密钥生成，将PS，X，IDb连起来
 */
unsigned char *KDF(element_t PS, element_t X, unsigned char *IDb) {
  unsigned char *key, *tem;
  char *SPS, *SX;
  int len;

  SPS = ele_to_str(PS);
  SX = ele_to_str(X);
  len = strlen(SPS) + strlen(SX) + KEM_PUBLICKEYBYTES;
  tem = (unsigned char *)malloc(len + 1);
  *tem = 0;

  strcpy((char *)tem, SPS);
  strcat((char *)tem, SX);
  memcpy(tem + len - KEM_PUBLICKEYBYTES, IDb, KEM_PUBLICKEYBYTES);
  tem[len] = 0;

  key = md5_16(tem);

  free(tem);
  free(SPS);
  free(SX);
  tem = NULL;
  return key;
}

/*
 *生成AES将要加密的明文
 */
struct str_s *PlainTXT(struct Plaintext_s *p, element_t x) {
  int offset = ZrLEN * 2;
  int cap = 0;
  struct str_s *plain = NULL;
  if (p == NULL) {
    printf("param error \n");
    exit(-1);
  }
  cap = ((plaintext_length(p) + offset + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) *
        AES_BLOCK_SIZE;

  unsigned char *xstr = NULL;
  plain = str_create();
  str_set(plain, cap, NULL);

  xstr = (unsigned char *)ele_to_str(x);
  str_set(plain, strlen((char *)xstr), xstr);
  str_add(plain, p->M);
  str_add(plain, p->ID);
  free(xstr);
  return plain;
}
