#ifndef _STR_H
#define _STR_H
#ifdef __cplusplus
extern "C" {
#endif

struct str_s {
  unsigned int length;
  unsigned int cap;
  unsigned char *data;
};

void str_release(struct str_s *str);

int str_set(struct str_s *str, unsigned int length, unsigned char *data);

unsigned char *str_get(struct str_s *str);

struct str_s *str_create(void);

unsigned int str_length(struct str_s *str);

struct str_s *str_add(struct str_s *dst, struct str_s *src);

int str_compare(struct str_s *str1, struct str_s *str2);

#ifdef __cplusplus
}
#endif
#endif // STR_H
