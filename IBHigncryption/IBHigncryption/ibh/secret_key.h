#ifndef _SECRET_KEY_H
#define _SECRET_KEY_H
#ifdef __cplusplus
extern "C" {
#endif

#include "str.h"

/*
 * 模式3下会生成两组密钥，分别用于加密与解密，加密时使用密钥1，解密时使用密钥2
 * 如果是模式1则生成密钥时只会生成一组密钥，即作加密也作解密
 */
struct secret_key_s {
  int  mode  ;
  struct str_s *sk[2];
};

/*
私钥对
*/
typedef struct secret_key_s secret_key;

void secret_key_release(secret_key *key);

secret_key *secret_key_create(void);

void secret_key_set0(secret_key *key, unsigned int length, unsigned char *data);

void secret_key_set1(secret_key *key, unsigned int length, unsigned char *data);

unsigned char *secret_key_get0(secret_key *key);

unsigned char *secret_key_get1(secret_key *key);

#ifdef __cplusplus
}
#endif
#endif // SECRET_KEY_H
