#ifndef _PLAINT_H
#define _PLAINT_H
#ifdef __cplusplus
extern "C" {
#endif

#include "str.h"

struct Plaintext_s {
  struct str_s *ID;
  struct str_s *M;
};

int plaintext_set_id(struct Plaintext_s *p, unsigned char *ID, int len);

int plaintext_set(struct Plaintext_s *p, unsigned char *m, int len);

unsigned char *plaintext_get_id(struct Plaintext_s *p);

unsigned char *plaintext_get(struct Plaintext_s *p);

void plaintext_release(struct Plaintext_s *p);

unsigned int plaintext_length(struct Plaintext_s *p);

struct Plaintext_s *plaintext_ceate(void);

#ifdef __cplusplus
}
#endif
#endif // PLAINT_H
