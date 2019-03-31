#ifndef IBH_H
#define IBH_H
#include "pbc/pbc.h"

#define SIG_SECRETKEYBYTES 16
#define SIG_BYTES 16
#define SIG_ALGNAME “IBHigncryption”

typedef struct{
    unsigned char* H;
    element_t X;
    unsigned char* Cae;
    size_t Mlen;
    size_t IDlen;
}Enc;

typedef struct{
    unsigned char* IDa;
    unsigned char* M;
}Dec;

void Init(element_t s,element_t q,element_t g1,element_t g2,pairing_t pairing);
void KeyGen(element_t ska1,element_t ska2,element_t s,unsigned char* IDa,pairing_t pairing);
Enc IBHigncrypt(unsigned char* H,element_t g1,element_t g2,element_t q,unsigned char* IDa,unsigned char* IDb,unsigned char* M,element_t ska1,pairing_t pairing);
Dec IBHigndecrypt(Enc enc,element_t skb2,unsigned char* IDb,pairing_t pairing);

#endif
