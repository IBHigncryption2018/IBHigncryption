#

CC=gcc -std=c99
DEPPATH=../3rd
INCL=-I $(DEPPATH)/pbc/include
LIBPATH=-L $(DEPPATH)/pbc/lib64

LIBS=-lssl -lcrypto -lgmp -lpbc
CFLAGS= -Wall -O3
DFLAG=-shared -fPIC 
COMMSRCS= ibh.c  md5.c  rand.c  sha.c  util.c str.c  plaint.c cipher.c 
SRCS3= $(COMMSRCS) kem_api.c secret_key.c 
SRCS1= $(COMMSRCS) kem_api_single.c secret_key1.c
TARGER3=../lib/libkem_api3.so
TARGER1=../lib/libkem_api1.so

all:clean $(TARGER1)   $(TARGER3)

$(TARGER3):
	$(CC) -o $(TARGER3) $(SRCS3) $(CFLAGS) $(INCL) $(LIBPATH) $(LIBS) $(DFLAG)

$(TARGER1):
	$(CC) -o $(TARGER1) $(SRCS1) $(CFLAGS) $(INCL) $(LIBPATH) $(LIBS) $(DFLAG)
clean:
	@rm -f $(TARGER3)
	@rm -f $(TARGER1)
