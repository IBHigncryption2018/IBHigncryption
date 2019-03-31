#include "util.h"


//输出十六进制为字符串
const char *dump_hex(unsigned char *s, unsigned int len) {
  static char buff[MAX_LEN * 8];
  memset(buff, 0, sizeof(buff));
  for (int i = 0; i < len && i < MAX_LEN * 8; i++) {
    sprintf(buff + i * 2, "%02X", s[i]);
  }
  return buff;
}

//将element_t格式转化为十六进制字符串
char *ele_to_str(element_t ele) {
  int i;
  int n = element_length_in_bytes(ele);
  unsigned char *tem = (unsigned char *)pbc_malloc(n);
  tem[0] = '\0';
  element_to_bytes(tem, ele);
  char *buf = (char *)malloc(n * 2 + 1);
  buf[0] = '\0';

  for (i = 0; i < n; i++) {
    sprintf(buf + i * 2, "%02X", tem[i]);
  }
  pbc_free(tem);
  tem = NULL;
  return buf;
}

//将十六进制形式表示的整数x转变为unsigned char字符串
void x_to_ele(element_t ele, unsigned char *data) {
  int i;
  unsigned char tem[ZrLEN + 1];
  for (i = 0; i < ZrLEN; i++) {
    tem[i] = 16 * (data[2 * i] > 60 ? (data[2 * i] - 55) : (data[2 * i] - 48));
    tem[i] += (data[2 * i + 1] > 60 ? (data[2 * i + 1] - 55)
                                    : (data[2 * i + 1] - 48));
  }
  tem[i] = '\0';
  element_from_bytes(ele, tem);
}

