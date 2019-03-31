#include "kem_api.h"

static inline unsigned long long cpucycles(void) {
  unsigned long long result;
  __asm__ volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
                   : "=a"(result)
                   :
                   : "%rdx");
  return result;
}

int main(int argc, char *argv[]) {
  char *para_file = NULL;
  secret_key *sk1 = NULL;
  secret_key *sk2 = NULL;
  struct Plaintext_s p1;
  struct ciphertext_s c;
  struct Plaintext_s p2;
  unsigned char ID1[KEM_PUBLICKEYBYTES + 1];
  unsigned char ID2[KEM_PUBLICKEYBYTES + 1];
  unsigned char M[M_LEN + 1];
  unsigned long long l1, l2;
  unsigned int num = 1;
  if (argc < 1) {
    printf("%s pairing file\n", argv[0]);
    return -1;
  }
  if (argc > 2) {
    num = atoi(argv[2]);
  }

  string_random(ID1, KEM_PUBLICKEYBYTES);
  string_random(ID2, KEM_PUBLICKEYBYTES);
  string_random(M, M_LEN);
  para_file = argv[1];
  kem_init(para_file);

  sk1 = secret_key_create();
  l1 = cpucycles();
  for (int i = 0; i < num; i++) {
    kem_keygen(ID1, (unsigned char *)sk1);
  }
  l2 = cpucycles();
  printf("%-20.40s compare cpucycles %d %lld averge %lld\n", "kem_keygen", num, l2 - l1,
         (l2 - l1) / num);

  sk2 = secret_key_create();
  kem_keygen(ID2, (unsigned char *)sk2);

  memset(&p1, 0, sizeof(p1));
  plaintext_set_id(&p1, ID1, KEM_PUBLICKEYBYTES);
  plaintext_set(&p1, M, M_LEN);
  memset(&c, 0, sizeof(c));

  l1 = cpucycles();
  for (int i = 0; i < num; i++) {
    if (kem_enc(ID2, (unsigned char *)&p1, secret_key_get0(sk1),
                (unsigned char *)&c)) {
      printf("enc error \n");
      return -1;
    }
  }
  l2 = cpucycles();
  printf("%-20.40s compare cpucycles %d %lld averge %lld\n", "kem_key_enc", num, l2 - l1,
         (l2 - l1) / num);

  memset(&p2, 0, sizeof(p2));
  l1 = cpucycles();
  for (int i = 0; i < num; i++) {
    if (kem_dec(secret_key_get1(sk2), (unsigned char *)&c, ID2,
                (unsigned char *)&p2)) {
      printf("dec error \n");
      return -1;
    }
  }
  l2 = cpucycles();
  printf("%-20.40s compare cpucycles %d %lld vaerge %lld\n", "kem_key_dec", num, l2 - l1,
         (l2 - l1) / num);

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
  return 0;
}
