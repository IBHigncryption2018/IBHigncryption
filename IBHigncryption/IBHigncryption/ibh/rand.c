
#include "rand.h"
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static int myrand(int seed) {
  static int seeds = 0;
  static int seedcounts = 0;
  seeds = seeds + seed + 0x9032 + seedcounts;
  srand(seeds);
  seedcounts = (seedcounts % 0x12354) + 1;
  return rand();
}

/**
 * Generate a random number of specified lengths
 *
 */
int string_random(unsigned char *msg, unsigned int length) {
  char *dict = "0123456789QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm";
  int seed = getpid() * 0x876;
  int len = strlen(dict);
  int i;
  for (i = 0; i < length; i++) {
    msg[i] = dict[myrand(seed) % len];
  }
  msg[i] = 0;
  return i;
}
