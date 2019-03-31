#include <stdlib.h>
#include <pbc/pbc.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#define ZrLEN 20
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

unsigned char* md5_16(unsigned char *data){
	unsigned char md[AES_BLOCK_SIZE],*res;
	int i;
	char tmp[3], buf[33] = {'\0'};
	MD5(data, sizeof(data), md);
	for(i = 4;i < 12;i++){//取32位md5值的中间16位为16位md5值
		sprintf(tmp, "%02x", md[i]);
		strcat(buf, tmp);
	}
	res=(unsigned char*)malloc(AES_BLOCK_SIZE*sizeof(unsigned char));
	for(i=0;i<AES_BLOCK_SIZE;i++){
        res[i]=buf[i];
	}
	res[i]='\0';
	return res;
}

unsigned char* sha1(unsigned char* data){
	unsigned char md[SHA_DIGEST_LENGTH],*res;
	int i;
	char tmp[3], buf[1025] = {'\0'};
	SHA1(data, sizeof(data), md);
	for(i = 0;i < SHA_DIGEST_LENGTH;i++){//取32位md5值的中间16位为16位md5值
		sprintf(tmp, "%02x", md[i]);
		strcat(buf, tmp);
	}
	res=(unsigned char*)malloc(SHA_DIGEST_LENGTH*sizeof(unsigned char));
	for(i=0;i<SHA_DIGEST_LENGTH;i++){
        res[i]=buf[i];
	}
	res[i]='\0';
	return res;
}

void Init(element_t s, element_t q, element_t g1, element_t g2, pairing_t pairing) {
	element_init_GT(q, pairing);
	element_init_G1(g1, pairing);
	element_init_G2(g2, pairing);
	element_init_Zr(s, pairing);
	element_random(s);
	element_random(q);
	element_random(g1);
	element_random(g2);
}

void KeyGen(element_t sk1,element_t sk2,element_t s,unsigned char* ID,pairing_t pairing){
    element_t h1,h2;
    element_init_G1(h1, pairing);
    element_init_G1(sk1, pairing);
    element_init_G2(h2, pairing);
    element_init_G2(sk2, pairing);
    unsigned char* shash1,*shash2;
    shash1 = md5_16(ID);
    element_from_hash(h1, shash1, AES_BLOCK_SIZE);//h=h(ID)
    element_pow_zn(sk1, h1, s);//sk=h^s
    shash2 = sha1(ID);
    element_from_hash(h2, shash2, AES_BLOCK_SIZE);//h=h(ID)
    element_pow_zn(sk2, h2, s);//sk=h^s
    free(shash1);shash1=NULL;free(shash2);shash2=NULL;
    element_clear(h1);element_clear(h2);
}

char* ele_to_str(element_t ele){
    int i;
    char tmp[3],*buf=(char*)malloc(1024);
    buf[0]='\0';
    int n = element_length_in_bytes(ele);
    unsigned char* tem = (unsigned char*)pbc_malloc(n);tem[0]='\0';
    element_to_bytes(tem, ele);
    for (i = 0; i < n; i++) {//将字符串以十六进制显示效果存储在buf中
        sprintf(tmp,"%02X", tem[i]);
        strcat(buf, tmp);
    }
    return buf;
}

void x_to_ele(element_t ele,unsigned char* data){//将十六进制形式表示的整数x转变为unsigned char字符串
    int i;
    unsigned char* tem=(unsigned char*)malloc(ZrLEN+1);
    tem[0]='\0';
    for(i=0;i<ZrLEN;i++){
        tem[i]=16*(data[2*i]>60?(data[2*i]-55):(data[2*i]-48));
        tem[i]+=(data[2*i+1]>60?(data[2*i+1]-55):(data[2*i+1]-48));
    }
    tem[i]='\0';
    element_from_bytes(ele, tem);
    free(tem);tem=NULL;
}

void get_info(element_t x,unsigned char* IDa,unsigned char* M,unsigned char* data,int ID_len,int data_len){//将解密得来的字符串，取出x,IDa,M;ID_len为ID长度
    unsigned char* tem=(unsigned char*)malloc(512);memset((unsigned char*)tem, 0, 512);
    int i;
    for(i=0;i<40;i++){
        tem[i]=data[i];
    }
    tem[i]='\0';

    x_to_ele(x,tem);//x

    for(i=ID_len;i>0;i--){//IDa
        IDa[ID_len-i]=data[data_len-i];
    }
    IDa[ID_len]='\0';

    for(i=40;i<data_len-ID_len;i++){//M
        M[i-40]=data[i];
    }
    M[i-40]='\0';
}

void cbc_encrypt(unsigned char *in,unsigned char *out,size_t len,const AES_KEY *key,unsigned char *ivec){
    size_t n;
    const unsigned char *iv=ivec;

    if(len==0)return;

    while(len){
        for(n=0;n<16&&n<len;++n)
            out[n]=in[n]^iv[n];
        for (;n<16;++n)
            out[n]=iv[n];
        AES_encrypt(out,out,key);
        iv=out;
        if(len<=16)
            break;
        len-=16;
        in+=16;
        out+=16;
    }
    memcpy(ivec,iv,16);
}

void cbc_decrypt(unsigned char *in,unsigned char *out,size_t len,const AES_KEY *key,unsigned char *ivec){
    size_t n;
    union{
        size_t t[16/sizeof(size_t)];
        unsigned char c[16];
    }tmp;

    if(len==0)return;

    while(len){
        unsigned char c;
        AES_decrypt(in,tmp.c,key);
        for(n=0;n<16&&n<len;++n){
            c=in[n];
            out[n]=tmp.c[n]^ivec[n];
            ivec[n]=c;
        }
        if(len<=16){
            for(;n<16;++n)ivec[n]=in[n];
            break;
        }
        len-=16;
        in+=16;
        out+=16;
    }
}

void ecb_encrypt(unsigned char *in,unsigned char *out,size_t len,const AES_KEY *key){

}

unsigned char* KDF(element_t PS,element_t X,unsigned char* IDb){
    unsigned char* key,*tem=(unsigned char*)malloc(513+strlen((char*)IDb));tem[0]='\0';
    char* str=(char*)malloc(513);str[0]='\0';
    char* SPS,*SX;
    int i,len,j;
    SPS=ele_to_str(PS);
    SX=ele_to_str(X);
    strcpy(str,SPS);
    strcat(str,SX);
    for(i=0;i<strlen(str);i++){
        tem[i]=str[i];
    }
    len=strlen((char*)IDb);
    for(j=0;j<len;j++){
        tem[i+j]=IDb[j];
    }
    tem[i+j]='\0';
    key=md5_16(tem);
    free(tem);tem=NULL;
    return key;
}

unsigned char* PlainTXT(unsigned char* IDa,unsigned char* M,element_t x){
    int lenID=-1,lenM=-1,i;
    while(IDa[++lenID]){}//字符串IDa的长度
    while(M[++lenM]){}//字符串M的长度

    unsigned char* plain=(unsigned char*)malloc((lenID+lenM+2*ZrLEN+1)*sizeof(unsigned char));
    plain[0]='\0';
    plain=(unsigned char*)ele_to_str(x);//x
    for(i=0;i<lenM;i++){//M
        plain[i+2*ZrLEN]=M[i];
    }
    for(i=0;i<lenID;i++){//IDa
        plain[i+2*ZrLEN+lenM]=IDa[i];
    }
    plain[lenID+lenM+2*ZrLEN]='\0';
    return plain;
}

Enc IBHigncrypt(unsigned char* H,element_t g1,element_t g2,element_t q,unsigned char* IDa,unsigned char* IDb,unsigned char* M,element_t SKa1,pairing_t pairing){
    int i;
    AES_KEY K1;
    Enc res;
    unsigned char *plain,*key,*iv;//aes.h中事先定义了块大小为16
    element_t x,tem,PS,ha1,hb2;
    element_init_G1(res.X, pairing);
    element_init_G1(ha1, pairing);
    element_init_G2(hb2, pairing);
    element_init_GT(tem, pairing);
    element_init_GT(PS, pairing);
    element_init_Zr(x, pairing);

    unsigned char* shash;
    shash = md5_16(IDa);
    element_from_hash(ha1, shash, AES_BLOCK_SIZE);//ha=h(IDa)
    shash = sha1(IDb);
    element_from_hash(hb2, shash, AES_BLOCK_SIZE);//hb=h(IDb)
    element_random(x);
    element_pow_zn(res.X,ha1,x);//X=ha^x
    pairing_apply(tem, SKa1,hb2,pairing);//tem=e(SKa,hb)
    element_pow_zn(PS,tem,x);//PS=tem^x

    //判断PS是否是单位元
    element_t ele_unit;
    element_init_GT(ele_unit,pairing);
    element_set1(ele_unit);
    if(!element_cmp(ele_unit, PS)){
        printf("加密过程得到了不符合规范的双线性对结果！\n");
        exit(1);
    }

    key=KDF(PS,res.X,IDb);
    AES_set_encrypt_key(key, AES_BLOCK_SIZE*8, &K1);//key

    iv = (unsigned char*)malloc(AES_BLOCK_SIZE);
    iv=md5_16(H);//iv

    plain=PlainTXT(IDa,M,x);
    res.Mlen = strlen((char*)plain);
    size_t length = ((res.Mlen+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE; //对齐分组
    res.Cae = (unsigned char*)malloc(length);memset((unsigned char*)res.Cae, 0, length);

    cbc_encrypt(plain, res.Cae, res.Mlen, &K1, iv);//encrypt

    int lenH=strlen((char*)H);
    res.H=(unsigned char*)malloc(lenH);
    for(i=0;i<lenH;i++){
        res.H[i]=H[i];
    }
    res.IDlen=strlen((char*)IDa);
    free(plain);free(key);free(iv);free(shash);shash=NULL;plain=NULL;key=NULL;iv=NULL;
    element_clear(x);element_clear(tem);element_clear(PS);element_clear(ha1);element_clear(hb2);
    return res;
}

Dec IBHigndecrypt(Enc enc,element_t skb2,unsigned char* IDb,pairing_t pairing){
    Dec res;
    element_t x,PS;
    element_init_GT(PS, pairing);
    element_init_Zr(x, pairing);
    AES_KEY de_key;
    size_t length = ((enc.Mlen+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;
    unsigned char* decrypt_result = (unsigned char*)malloc(length);
    unsigned char* iv=(unsigned char*)malloc(AES_BLOCK_SIZE);
    memset((unsigned char*)decrypt_result, 0, length);

    pairing_apply(PS, enc.X,skb2,pairing);//PS=e(X,skb)
    //判断PS是否是单位元
    element_t ele_unit;
    element_init_GT(ele_unit,pairing);
    element_set1(ele_unit);
    if(!element_cmp(ele_unit, PS)){
        printf("解密过程得到了不符合规范的双线性对结果！\n");
        exit(1);
    }

    unsigned char* key=KDF(PS,enc.X,IDb);
    AES_set_decrypt_key(key, AES_BLOCK_SIZE*8, &de_key);//key
    iv=md5_16(enc.H);//iv
    cbc_decrypt(enc.Cae, decrypt_result, enc.Mlen, &de_key, iv);//decrypt
    res.IDa=(unsigned char*)malloc(enc.Mlen),res.M=(unsigned char*)malloc(enc.Mlen);

    get_info(x,res.IDa,res.M,decrypt_result,enc.IDlen,enc.Mlen);
    element_clear(PS);

    //compare
    element_t tem,ha1;
    element_init_G1(tem, pairing);
    element_init_G1(ha1, pairing);
    unsigned char* shash;
    shash = md5_16(res.IDa);
    element_from_hash(ha1, shash, AES_BLOCK_SIZE);//ha=h(IDa)
    element_pow_zn(tem,ha1,x);//tem=ha^x
    if (!element_cmp(tem,enc.X) && pairing->Zr==x->field) {//验证x属于Zr且X=h^x
		printf("IDs验证成功！\n");
		return res;
	}
	else {
		printf("IDs验证出错！\n");
		exit(1);
	}
	free(decrypt_result);free(iv);free(shash);shash=NULL;decrypt_result=NULL;iv=NULL;
	element_clear(tem);element_clear(x);element_clear(ha1);
}
