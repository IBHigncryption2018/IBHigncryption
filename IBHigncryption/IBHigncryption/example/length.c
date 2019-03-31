
#include "kem_api.h"

int main(int argc, char *argv[]) {
  secret_key *sk1 = NULL;
  secret_key *sk2 = NULL;
  struct Plaintext_s p1;
  struct ciphertext_s c;
  struct Plaintext_s p2;
  int len = 32;
  struct str_s *M = NULL;

  unsigned char ID1[KEM_PUBLICKEYBYTES + 1];
  unsigned char ID2[KEM_PUBLICKEYBYTES + 1];

  if (argc < 3) {
    printf("%s pairing file length \n", argv[0]);
    return -1;
  }

  char *para_file = argv[1];
  len = atoi(argv[2]);
  M = str_create();
  str_set(M, len, NULL);
  string_random(ID1, KEM_PUBLICKEYBYTES);
  string_random(ID2, KEM_PUBLICKEYBYTES);
  M->length = string_random(str_get(M), len);

  kem_init(para_file);

  sk1 = secret_key_create();
  kem_keygen(ID1, (unsigned char *)sk1);

  sk2 = secret_key_create();
  kem_keygen(ID2, (unsigned char *)sk2);

  memset(&p1, 0, sizeof(p1));
  plaintext_set_id(&p1, ID1, KEM_PUBLICKEYBYTES);
  plaintext_set(&p1, str_get(M), len);

  memset(&c, 0, sizeof(c));
  if (kem_enc(ID2, (unsigned char *)&p1, secret_key_get0(sk1),
              (unsigned char *)&c)) {
    printf("enc error \n");
    return -1;
  }
  memset(&p2, 0, sizeof(p2));
  if (kem_dec(secret_key_get1(sk2), (unsigned char *)&c, ID2,
              (unsigned char *)&p2)) {
    printf("dec error \n");
    return -1;
  }
  if (str_compare(p1.ID, p2.ID) || str_compare(p1.M, p2.M)) {
    printf("%-20.40s compare error \n", argv[0]);
  } else {
    printf("%-20.40s compare OK \n", argv[0]);
    printf("enc ID=%d: %s\n", str_length(p1.ID), plaintext_get_id(&p1));
    printf("enc M=%d: %s\n", str_length(p1.M), plaintext_get(&p1));
    printf("dec ID=%d: %s\n", str_length(p2.ID), str_get(p2.ID));
    printf("dec M=%d: %s\n", str_length(p2.M), str_get(p2.M));
  }
  secret_key_release(sk1);
  secret_key_release(sk2);
  plaintext_release(&p1);
  cipertext_release(&c);
  return 0;
}
