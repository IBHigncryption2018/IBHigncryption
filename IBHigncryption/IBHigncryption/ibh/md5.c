#include "md5.h"
#include "ibh.h"


unsigned char *md5_16(unsigned char *data) {
  unsigned char md[AES_BLOCK_SIZE + 1], *res;
  int i, j;
  char buf[33] = {'\0'};

  MD5(data, strlen((char *)data), md);
  j = 0;
  //取32位md5值的中间16位为16位md5值
  for (i = 4, j = 0; i < 12; i++, j++) {
    sprintf(buf + j * 2, "%02x", md[i]);
  }
  res = (unsigned char *)malloc(AES_BLOCK_SIZE * sizeof(unsigned char) + 1);
  for (i = 0; i < AES_BLOCK_SIZE; i++) {
    res[i] = buf[i];
  }
  res[i] = '\0';
  return res;
}

unsigned char *md5_32(unsigned char *data) {
	unsigned char md[AES_BLOCK_SIZE + 1], *res;
	int i;
	char buf[33] = { '\0' };

	MD5(data, strlen((char *)data), md);
	for (i = 0; i < 16; i++) {
		sprintf(buf + i * 2, "%02x", md[i]);
	}
	res = (unsigned char *)malloc(2 * AES_BLOCK_SIZE * sizeof(unsigned char) + 1);
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		res[i] = buf[i];
	}
	res[i] = '\0';
	return res;
}