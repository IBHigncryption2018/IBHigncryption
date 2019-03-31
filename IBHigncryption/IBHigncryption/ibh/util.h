#ifndef _UTIL_H
#define _UTIL_H
#ifdef __cplusplus
extern "C" {
#endif

#include <pbc/pbc.h>
#include "ibh.h"

const char *dump_hex(unsigned char *s, unsigned int len);
char *ele_to_str(element_t ele);
void x_to_ele(element_t ele, unsigned char *data);

#ifdef __cplusplus
}
#endif
#endif // UTIL_H
