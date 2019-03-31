
#include "plaint.h"
#include "ibh.h"
#include "str.h"
#include <stdlib.h>

void plaintext_release(struct Plaintext_s *p) {
  if (p->ID) {
    str_release(p->ID);
    p->ID = NULL;
  }
  if (p->M) {
    str_release(p->M);
    p->M = NULL;
  }
}

struct Plaintext_s *plaintext_ceate(void) {
  struct Plaintext_s *p;
  p = malloc(sizeof(struct Plaintext_s));
  if (p) {
    p->ID = str_create();
    p->M = str_create();
  }
  return p;
}

int plaintext_set_id(struct Plaintext_s *p, unsigned char *ID, int len) {
  if (p->ID == NULL) {
    p->ID = str_create();
  }
  str_set(p->ID, len, ID);
  return 0;
}

int plaintext_set(struct Plaintext_s *p, unsigned char *m, int len) {
  if (p->M == NULL) {
    p->M = str_create();
  }
  str_set(p->M, len, m);
  return 0;
}

unsigned char *plaintext_get_id(struct Plaintext_s *p) {
  return str_get(p->ID);
}

unsigned int plaintext_get_id_length(struct Plaintext_s *p) {
  return str_length(p->ID);
}

unsigned char *plaintext_get(struct Plaintext_s *p) { return str_get(p->M); }

unsigned int plaintext_length(struct Plaintext_s *p) {
  return str_length(p->M) + str_length(p->ID);
}
