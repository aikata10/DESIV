#define CRYPTO_KEYBYTES 16
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 32

#define MAX_MESSAGE_LENGTH 32
#define MAX_ASSOCIATED_DATA_LENGTH 32


#include "encrypt.c"
#include <stdio.h>
#include <string.h>
#include <time.h>

 int main(){
	 unsigned long long mlen = MAX_MESSAGE_LENGTH;
	 unsigned char	ad[MAX_ASSOCIATED_DATA_LENGTH] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F};
	 unsigned long long adlen = MAX_ASSOCIATED_DATA_LENGTH;
	 unsigned char	nonce[CRYPTO_NPUBBYTES] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
	 unsigned char	ct[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES];
	 unsigned long long  clen;
	 unsigned char	msg[MAX_MESSAGE_LENGTH] ;

         unsigned char key[CRYPTO_KEYBYTES] ;

	int i=0;
         for (i=0;i<32;i++)
         {
                      time_t t;
                      srand((unsigned) time(&t));
		      msg[i]=rand()%256;
         }


         i=0;

         for (i=0;i<16;i++)
         {
                      time_t t;
                      srand((unsigned) time(&t));
		      key[i]=rand()%256;
         }

	 
	 crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key);
	 
	/* printf("\nC : ");
	 for(unsigned long long i=0; i<mlen; i++){
		 printf("%d ",ct[i]);
	 }
	 
	 printf("\nT : ");
	 for(unsigned long long i=mlen; i<mlen + CRYPTO_ABYTES; i++){
		 printf("%d ",ct[i]);
	 }
	 printf("\n");*/
	 return 0;
}
