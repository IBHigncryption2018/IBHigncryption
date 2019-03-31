#include "sha.h"
#include "ibh.h"

unsigned char *sha1(unsigned char *data) {
  unsigned char md[SHA_DIGEST_LENGTH + 1];
  int i;
  int len = SHA_DIGEST_LENGTH * 2;

  unsigned char *res = (unsigned char *)malloc(len * sizeof(unsigned char) + 1);

  SHA1(data, strlen((char *)data), md);
  for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
    snprintf((char *)res + i * 2, len, "%02x", md[i]);
  }
  res[len] = 0;
  return res;
}
