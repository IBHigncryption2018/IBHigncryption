#ifndef _CIPHER_H
#define _CIPHER_H
#ifdef __cplusplus
extern "C" {
#endif
#include "str.h"

/*
 * IBHigncryption 加密后生成的密文包含两部分，一部分为密文数据CT，另外一部分为证书cert
 */
struct ciphertext_s {
  struct str_s *CT;
  struct str_s *cert;
};

int cipertext_set_cert(struct ciphertext_s *c, unsigned char *cert, int len);

int cipertext_set(struct ciphertext_s *c, unsigned char *m, int len);

unsigned char *cipertext_get_cert(struct ciphertext_s *c);

unsigned char *cipertext_get(struct ciphertext_s *c);

void cipertext_release(struct ciphertext_s *p);

struct ciphertext_s *cipertext_create(void);

#ifdef __cplusplus
}
#endif
#endif // CIPHER_H
