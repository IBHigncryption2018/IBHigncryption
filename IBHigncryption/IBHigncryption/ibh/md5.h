#ifndef _MD5_H
#define _MD5_H
#ifdef __cplusplus
extern "C" {
#endif

unsigned char *md5_16(unsigned char *data);
unsigned char *md5_32(unsigned char *data);

#ifdef __cplusplus
}
#endif
#endif // MD5_H
