
#include "ibh.h"
#include "kem_api.h"
#include "secret_key.h"
#include "string.h"
#include <pbc/pbc_test.h>

#include "ibh.h"
#include "rand.h"
#include "util.h"
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <pbc/pbc.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static char *para_file = "/home/develop/Downloads/pbc-0.5.14/param/a.param";

#if 0
static inline unsigned long long cpucycles(void)          
{                                                 
    unsigned int lo,hi;                           
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;             
}

#else
static inline long long cpucycles(void) {
  unsigned long long result;
  __asm__ volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
                   : "=a"(result)
                   :
                   : "%rdx");
  return result;
}
#endif

int test_api_cpu(char *file) {
  secret_key *sk1 = NULL;
  secret_key *sk2 = NULL;
  struct Plaintext_s p1;
  struct ciphertext_s c;
  struct Plaintext_s p2;

  unsigned char ID1[KEM_PUBLICKEYBYTES + 1];
  unsigned char ID2[KEM_PUBLICKEYBYTES + 1];
  unsigned char M[M_LEN + 1];
  unsigned long long l1, l2;

  string_random(ID1, KEM_PUBLICKEYBYTES);
  string_random(ID2, KEM_PUBLICKEYBYTES);
  string_random(M, M_LEN);

  kem_init(para_file);

  sk1 = secret_key_create();
  l1 = cpucycles();
  kem_keygen(ID1, (unsigned char *)sk1);
  l2 = cpucycles();
  printf("%-20.40s cpucycles %d\n", "kem_keygen", l2 - l1);

  sk2 = secret_key_create();
  kem_keygen(ID2, (unsigned char *)sk2);

  memset(&p1, 0, sizeof(p1));
  memcpy(p1.ID, ID1, KEM_PUBLICKEYBYTES);
  memcpy(p1.M, M, M_LEN);
  memset(&c, 0, sizeof(c));

  l1 = cpucycles();
  if (kem_enc(ID2, (unsigned char *)&p1, secret_key_get0(sk1),
              (unsigned char *)&c)) {
    printf("enc error \n");
    return -1;
  }
  l2 = cpucycles();
  printf("%-20.40s cpucycles %d\n", "kem_key_enc", l2 - l1);

  memset(&p2, 0, sizeof(p2));
  l1 = cpucycles();
  if (kem_dec(secret_key_get1(sk2), (unsigned char *)&c, ID2,
              (unsigned char *)&p2)) {
    printf("dec error \n");
    return -1;
  }
  l2 = cpucycles();
  printf("%-20.40s cpucycles %d\n", "kem_key_dec", l2 - l1);
  secret_key_release(sk1);
  secret_key_release(sk2);
  return 0;
}

int test_api_func1(char *file) {
  secret_key *sk1 = NULL;
  secret_key *sk2 = NULL;
  struct Plaintext_s p1;
  struct ciphertext_s c;
  struct Plaintext_s p2;

  unsigned char ID1[KEM_PUBLICKEYBYTES + 1];
  unsigned char ID2[KEM_PUBLICKEYBYTES + 1];
  unsigned char M[M_LEN + 1];

  string_random(ID1, KEM_PUBLICKEYBYTES);
  string_random(ID2, KEM_PUBLICKEYBYTES);
  string_random(M, M_LEN);

  printf("M=%s\n", M);
  printf("Mlen0=%d\n", strlen((char *)M));
  printf("ID1=%s\n", ID1);
  printf("ID2=%s\n", ID2);

  kem_init(para_file);

  sk1 = secret_key_create();
  kem_keygen(ID1, (unsigned char *)sk1);

  sk2 = secret_key_create();
  kem_keygen(ID2, (unsigned char *)sk2);

  memset(&p1, 0, sizeof(p1));
  memcpy(p1.ID, ID1, KEM_PUBLICKEYBYTES);
  memcpy(p1.M, M, M_LEN);
  printf("p1.M=%s\n", p1.M);
  memset(&c, 0, sizeof(c));

  if (kem_enc(ID2, (unsigned char *)&p1, secret_key_get0(sk1),
               (unsigned char *)&c)) {
    printf("enc error \n");
    return -1;
  }

  printf("ct_len=%d [%s]\n", c.ct_len, dump_hex(c.CT, c.ct_len));
  memset(&p2, 0, sizeof(p2));
  if (kem_dec(secret_key_get0(sk2), (unsigned char *)&c, ID2,
               (unsigned char *)&p2)) {
    printf("dec error \n");
    return -1;
  }
  printf("ID2=%s\n", p2.ID);
  printf("M2=%s\n", p2.M);
  secret_key_release(sk1);
  secret_key_release(sk2);
  return 0;
}

int test_api_func(char *file) {
  secret_key *sk1 = NULL;
  secret_key *sk2 = NULL;
  struct Plaintext_s p1;
  struct ciphertext_s c;
  struct Plaintext_s p2;

  unsigned char ID1[KEM_PUBLICKEYBYTES + 1];
  unsigned char ID2[KEM_PUBLICKEYBYTES + 1];
  unsigned char M[M_LEN + 1];

  string_random(ID1, KEM_PUBLICKEYBYTES);
  string_random(ID2, KEM_PUBLICKEYBYTES);
  string_random(M, M_LEN);

  printf("M=%s\n", M);
  printf("Mlen0=%d\n", strlen((char *)M));
  printf("ID1=%s\n", ID1);
  printf("ID2=%s\n", ID2);

  kem_init(para_file);

  sk1 = secret_key_create();
  kem_keygen(ID1, (unsigned char *)sk1);

  sk2 = secret_key_create();
  kem_keygen(ID2, (unsigned char *)sk2);

  memset(&p1, 0, sizeof(p1));
  memcpy(p1.ID, ID1, KEM_PUBLICKEYBYTES);
  memcpy(p1.M, M, M_LEN);
  printf("p1.M=%s\n", p1.M);
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
  printf("ID2=%s\n", p2.ID);
  printf("M2=%s\n", p2.M);
  secret_key_release(sk1);
  secret_key_release(sk2);
  return 0;
}
/*
 */
int test_api_func2(char *file) {
  secret_key *sk1 = NULL;
  secret_key *sk2 = NULL;
  secret_key *sk3 = NULL;
  struct Plaintext_s p1;
  struct ciphertext_s c;
  struct Plaintext_s p2;

  unsigned char ID1[KEM_PUBLICKEYBYTES + 1];
  unsigned char ID2[KEM_PUBLICKEYBYTES + 1];
  unsigned char ID3[KEM_PUBLICKEYBYTES + 1];
  unsigned char M[M_LEN + 1];

  string_random(ID1, KEM_PUBLICKEYBYTES);
  string_random(ID2, KEM_PUBLICKEYBYTES);
  string_random(ID3, KEM_PUBLICKEYBYTES);
  string_random(M, M_LEN);

  printf("M=%s\n", M);
  printf("Mlen0=%d\n", strlen((char *)M));
  printf("ID1=%s\n", ID1);
  printf("ID2=%s\n", ID2);

  kem_init(para_file);

  sk1 = secret_key_create();
  kem_keygen(ID1, (unsigned char *)sk1);

  sk2 = secret_key_create();
  kem_keygen(ID2, (unsigned char *)sk2);

  sk3 = secret_key_create();
  kem_keygen(ID3, (unsigned char *)sk3);

  memset(&p1, 0, sizeof(p1));
  memcpy(p1.ID, ID1, KEM_PUBLICKEYBYTES);
  memcpy(p1.M, M, M_LEN);
  printf("p1.M=%s\n", p1.M);
  memset(&c, 0, sizeof(c));

  printf("ID1 enc sk2 ID2 enc OK\n");
  if (kem_enc(ID2, (unsigned char *)&p1, secret_key_get0(sk1),
              (unsigned char *)&c)) {
    printf("enc error \n");
    return -1;
  }

  memset(&p2, 0, sizeof(p2));
  if (kem_dec(secret_key_get1(sk3), (unsigned char *)&c, ID2,
              (unsigned char *)&p2)) {
    printf("dec sk3 ID2 Verification OK\n");
  }
  if (kem_dec(secret_key_get1(sk3), (unsigned char *)&c, ID3,
              (unsigned char *)&p2)) {
    printf("dec sk3 ID3 Verification OK\n");
  }
  if (kem_dec(secret_key_get1(sk2), (unsigned char *)&c, ID2,
              (unsigned char *)&p2)) {
    printf("dec sk2 ID2 Verification OK\n");
  }
  if (kem_dec(secret_key_get1(sk2), (unsigned char *)&c, ID3,
              (unsigned char *)&p2)) {
    printf("dec sk2 ID3 Verification OK\n");
  }
  secret_key_release(sk1);
  secret_key_release(sk2);
  secret_key_release(sk3);
  return 0;
}

int test_api(char *file, int num) {
  secret_key *sk1 = NULL;
  secret_key *sk2 = NULL;
  struct Plaintext_s p1;
  struct ciphertext_s c;
  struct Plaintext_s p2;

  unsigned char ID1[KEM_PUBLICKEYBYTES + 1];
  unsigned char ID2[KEM_PUBLICKEYBYTES + 1];
  unsigned char M[M_LEN + 1];

  memset(ID1, 0, sizeof(ID1));
  memset(ID2, 0, sizeof(ID2));
  memset(M, 0, sizeof(M));
  string_random(ID1, KEM_PUBLICKEYBYTES);
  string_random(ID2, KEM_PUBLICKEYBYTES);
  string_random(M, M_LEN);

  kem_init(para_file);

  sk1 = secret_key_create();
  kem_keygen(ID1, (unsigned char *)sk1);

  sk2 = secret_key_create();
  kem_keygen(ID2, (unsigned char *)sk2);

  double t0, t1;
  unsigned int succ_total = 0, fail_total = 0;

  string_random(M, M_LEN);
  memset(&p1, 0, sizeof(p1));
  memcpy(p1.ID, ID1, KEM_PUBLICKEYBYTES);
  memcpy(p1.M, M, M_LEN);
  memset(&c, 0, sizeof(c));
  t0 = pbc_get_time();
  memset(&p2, 0, sizeof(p2));
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
  printf("%-20.40s success %d/%d fail:%d average  time = %f\n",
         __FUNCTION__, succ_total, num, fail_total, (t1 - t0) / num);
  secret_key_release(sk1);
  secret_key_release(sk2);
  return 0;
}

int test_api_all(char *file, int num) {
  secret_key *sk1 = NULL;
  secret_key *sk2 = NULL;
  struct Plaintext_s p1;
  struct ciphertext_s c;
  struct Plaintext_s p2;

  unsigned char ID1[KEM_PUBLICKEYBYTES + 1];
  unsigned char ID2[KEM_PUBLICKEYBYTES + 1];
  unsigned char M[M_LEN + 1];
  double t0, t1;
  unsigned int succ_total = 0, fail_total = 0;

  memset(ID1, 0, sizeof(ID1));
  memset(ID2, 0, sizeof(ID2));
  memset(M, 0, sizeof(M));
  string_random(ID1, KEM_PUBLICKEYBYTES);
  string_random(ID2, KEM_PUBLICKEYBYTES);
  string_random(M, M_LEN);

  kem_init(para_file);
  sk1 = secret_key_create();
  sk2 = secret_key_create();
  string_random(M, M_LEN);

  memset(&p1, 0, sizeof(p1));
  memcpy(p1.ID, ID1, KEM_PUBLICKEYBYTES);
  memcpy(p1.M, M, M_LEN);
  memset(&c, 0, sizeof(c));
  memset(&p2, 0, sizeof(p2));
  t0 = pbc_get_time();
  for (int i = 0; i < num; i++) {
    kem_keygen(ID1, (unsigned char *)sk1);
    kem_keygen(ID2, (unsigned char *)sk2);
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
  printf("%-20.40s success %d/%d fail:%d average time= %f total time=%f\n",
         __FUNCTION__, succ_total, num, fail_total, (t1 - t0) / num, t1-t0);
  secret_key_release(sk1);
  secret_key_release(sk2);
  return 0;
}

int main(int argc, char *argv[]) {
  int num = 1;
  if (argc > 1) {
    num = atoi(argv[1]);
  }
  test_api_func(para_file);
  test_api_func2(para_file);
  test_api(para_file, num);
  test_api_all(para_file, num);
  test_api_cpu(para_file);
  test_api_func1(para_file);
  return 0;
}
