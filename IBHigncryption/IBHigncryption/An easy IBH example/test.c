#include "IBH.h"
#include "string.h"

int main(int argc, char **argv) {
    pairing_t pairing;
    element_t s,q,g1,g2,ska1,ska2,skb1,skb2;
    unsigned char *H=(unsigned char*)"HHHHHHHH2",*M=(unsigned char*)"2MMMMMMMMMMMMMMMMmmmmmmMMMMMMMMMMMMMMMMMMMMM",*IDa=(unsigned char*)"IDaIDaIDa2",*IDb=(unsigned char*)"IDbIDbIDb2";
    Enc enc;
    Dec dec;

    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);

    printf("IDa=%s\n",IDa);
    printf("IDb=%s\n",IDb);
    printf("M=%s\n",M);
    printf("H=%s\n",H);

    printf("\n初始化：\n");
    Init(s,q,g1,g2,pairing);
    element_printf("g1=%B\n",g1);
    element_printf("g2=%B\n",g2);
    element_printf("q=%B\n",q);
    element_printf("s=%B\n",s);
    KeyGen(ska1,ska2,s,IDa,pairing);
    element_printf("SKa1=%B\n",ska1);
    element_printf("SKa2=%B\n",ska2);
    KeyGen(skb1,skb2,s,IDb,pairing);
    element_printf("SKb1=%B\n",skb1);
    element_printf("SKb2=%B\n",skb2);

    printf("\n加密：\n");
    enc=IBHigncrypt(H,g1,g2,q,IDa,IDb,M,ska1,pairing);
    printf("加密结果为：%s\n",enc.Cae);

    printf("\n解密：\n");
    dec=IBHigndecrypt(enc,skb2,IDb,pairing);
    printf("IDa=%s\n",dec.IDa);
    printf("M=%s\n",dec.M);
}
