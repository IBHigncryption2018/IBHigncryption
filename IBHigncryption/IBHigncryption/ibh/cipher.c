#include "cipher.h"
#include "str.h"
#include <stdlib.h>

void cipertext_release(struct ciphertext_s *p) {
  if (p) {
    if (p->CT) {
      str_release(p->CT);
      p->CT = NULL;
    }
    if (p->cert) {
      str_release(p->cert);
      p->cert = NULL;
    }
  }
}

struct ciphertext_s *cipertext_create(void) {
  struct ciphertext_s *c;
  c = malloc(sizeof(struct ciphertext_s));
  if (c) {
    c->CT = str_create();
    c->cert = str_create();
  }
  return c;
}

int cipertext_set_cert(struct ciphertext_s *c, unsigned char *cert, int len) {
  if (c->cert == NULL) {
    c->cert = str_create();
  }
  str_set(c->cert, len, cert);
  return 0;
}

int cipertext_set(struct ciphertext_s *c, unsigned char *m, int len) {
  if (c->CT == NULL) {
    c->CT = str_create();
  }
  str_set(c->CT, len, m);
  return 0;
}

unsigned char *cipertext_get_cert(struct ciphertext_s *c) {
  return str_get(c->cert);
}

unsigned char *cipertext_get(struct ciphertext_s *c) { return str_get(c->CT); }
