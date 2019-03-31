#include "str.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * 封装简单字符串操作
 */
void str_release(struct str_s *str) {
  if (str) {
    if (str->data) {
      free(str->data);
      str->data = NULL;
    }
    free(str);
    str = NULL;
  }
}

struct str_s *str_create(void) {
  struct str_s *s = NULL;
  s = malloc(sizeof(struct str_s));
  s->length = 0;
  s->cap = 0;
  s->data = NULL;
  return s;
}

int str_set(struct str_s *str, unsigned int length, unsigned char *data) {
  if (str == NULL) {
    return -1;
  }
  int zero_flg = 1;
  if (!str->data) {
    str->data = malloc(sizeof(unsigned char) * length + 1);
    str->cap = length;
  } else if (str->cap < length) {
    str->data = realloc(str->data, sizeof(unsigned char) * length + 1);
    zero_flg = 0;
    str->cap = length;
  }
  if (!str->data) {
    printf("malloc error\n");
    exit(0);
  }
  if (data) {
    str->length = length;
    memcpy(str->data, data, length);
    str->data[length] = 0;
  } else if (zero_flg == 1) {
    memset(str->data, 0, str->cap);
  }
  return length;
}

struct str_s *str_add(struct str_s *dst, struct str_s *src) {
  if (dst->cap < dst->length + src->length) {
    str_set(dst, dst->length + src->length, NULL);
  }
  memcpy(dst->data + dst->length, src->data, src->length);
  dst->length += src->length;
  dst->data[dst->length] = 0;
  return dst;
}

unsigned char *str_get(struct str_s *str) { return str->data; }

unsigned int str_length(struct str_s *str) { return str->length; }

int str_compare(struct str_s *str1, struct str_s *str2) {
  return str1->length == str2->length &&
         memcmp(str1->data, str2->data, str1->length);
}
