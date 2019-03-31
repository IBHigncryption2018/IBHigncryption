#include "secret_key.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void secret_key_set0(secret_key *key, unsigned int length, unsigned char *data) {
  str_set(key->sk[0], length, data);
}

void secret_key_set1(secret_key *key, unsigned int length, unsigned char *data) {
  str_set(key->sk[1], length, data);
}

unsigned char *secret_key_get0(secret_key *key) { return str_get(key->sk[0]); }

unsigned char *secret_key_get1(secret_key *key) { return str_get(key->sk[1]); }

secret_key *secret_key_create(void) {
  secret_key *key = malloc(sizeof(secret_key));
  if (!key) {
    return NULL;
  }
  key->sk[0] = str_create();
  key->sk[1] = str_create();
  return key;
}

void secret_key_release(secret_key *key) {
  if (key) {
    if (key->sk[0]) {
      str_release(key->sk[0]);
    }
    if (key->sk[0]) {
      str_release(key->sk[1]);
    }
    free(key);
    key = NULL;
  }
}

