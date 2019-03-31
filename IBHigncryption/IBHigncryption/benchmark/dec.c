
#include "kem_api.h"

int main(int argc, char *argv[]) {
  secret_key *sk1 = NULL;
  secret_key *sk2 = NULL;
  struct Plaintext_s p1;
  struct ciphertext_s c;
  struct Plaintext_s p2;
  int num = 100;
  char *para_file = NULL;

  unsigned char ID1[KEM_PUBLICKEYBYTES + 1];
  unsigned char ID2[KEM_PUBLICKEYBYTES + 1];
  unsigned char M[M_LEN + 1];

  memset(ID1, 0, sizeof(ID1));
  memset(ID2, 0, sizeof(ID2));
  memset(M, 0, sizeof(M));
  string_random(ID1, KEM_PUBLICKEYBYTES);
  string_random(ID2, KEM_PUBLICKEYBYTES);
  string_random(M, M_LEN);
  if (argc < 1) {
    printf("%s parafile \n", argv[0]);
    return -1;
  }
  para_file = argv[1];
  kem_init(para_file);

  if (num > 2) {
    num = atoi(argv[2]);
  }
  sk1 = secret_key_create();
  kem_keygen(ID1, (unsigned char *)sk1);

  sk2 = secret_key_create();
  kem_keygen(ID2, (unsigned char *)sk2);

  double t0, t1;
  unsigned int succ_total = 0, fail_total = 0;

  string_random(M, M_LEN);
  memset(&p1, 0, sizeof(p1));
  plaintext_set_id(&p1, ID1, KEM_PUBLICKEYBYTES);
  plaintext_set(&p1, M, M_LEN);

  memset(&c, 0, sizeof(c));
  memset(&p2, 0, sizeof(p2));

  if (kem_enc(ID2, (unsigned char *)&p1, secret_key_get0(sk1),
              (unsigned char *)&c)) {
    printf("enc error \n");
    return -1;
  }

  t0 = pbc_get_time();
  for (int i = 0; i < num; i++) {
    if (kem_dec(secret_key_get1(sk2), (unsigned char *)&c, ID2,
                (unsigned char *)&p2)) {
      printf("dec error \n");
      fail_total++;
    } else {
      succ_total++;
    }
  }
  t1 = pbc_get_time();
  printf("%-20.40s success %d/%d fail:%d average time = %f total time = %f\n", "dec",
         succ_total, num, fail_total, (t1 - t0) / num, t1-t0);
  secret_key_release(sk1);
  secret_key_release(sk2);
  plaintext_release(&p1);
  cipertext_release(&c);
  return 0;
}
