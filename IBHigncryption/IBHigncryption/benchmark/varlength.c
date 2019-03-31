#include "kem_api.h"

int main(int argc, char *argv[]) {
  secret_key *sk1 = NULL;
  secret_key *sk2 = NULL;
  struct Plaintext_s p1;
  struct ciphertext_s c;
  struct Plaintext_s p2;
  int len = 32;
  int num = 100;
  struct str_s *M = NULL;

  unsigned char ID1[KEM_PUBLICKEYBYTES + 1];
  unsigned char ID2[KEM_PUBLICKEYBYTES + 1];

  if (argc < 4) {
    printf("%s pairing file length \n", argv[0]);
    return -1;
  }
  num = atoi(argv[2]);
  len = atoi(argv[3]);
  char *para_file = argv[1];
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

  double t0, t1;
  unsigned int succ_total = 0, fail_total = 0;

  memset(&c, 0, sizeof(c));
  memset(&p2, 0, sizeof(p2));
  t0 = pbc_get_time();
  for (int i = 0; i < num; i++) {
    if (kem_enc(ID2, (unsigned char *)&p1, secret_key_get0(sk1),
                (unsigned char *)&c)) {
      printf("enc error \n");
      return -1;
    }
    if (kem_dec(secret_key_get1(sk2), (unsigned char *)&c, ID2,
                (unsigned char *)&p2)) {
      printf("dec error \n");
      fail_total++;
    } else {
      succ_total++;
    }
  }
  t1 = pbc_get_time();
  printf("%-20.40s success %d/%d fail:%d average time = %f total time = %f data len= %d\n",
         "enc_dec_length", succ_total, num, fail_total, (t1 - t0) / num, t1 - t0, len);
  if (str_compare(p1.ID, p2.ID) || str_compare(p1.M, p2.M)) {
    printf("compare error \n");
  }
  secret_key_release(sk1);
  secret_key_release(sk2);
  plaintext_release(&p1);
  cipertext_release(&c);
  str_release(M);
  return 0;
}
