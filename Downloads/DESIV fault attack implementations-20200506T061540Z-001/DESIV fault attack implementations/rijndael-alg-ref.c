/* rijndael-alg-ref.c   v2.0   August '99
 * Reference ANSI C code
 * authors: Paulo Barreto
 *          Vincent Rijmen
 */
/*
                        ------------------------------
                        Rijndael ANSI C Reference Code
                        ------------------------------

                                October 24, 2000

                                  Disclaimer


This software package was submitted to the National Institute of Standards and
Technology (NIST) during the Advanced Encryption Standard (AES) development
effort by Joan Daemen and Vincent Rijmen, the developers of the Rijndael algorithm.

This software is distributed in compliance with export regulations (see below), and
it is intended for non-commercial use, only.   NIST does not support this software 
and does not provide any guarantees or warranties as to its performance, fitness 
for any particular application, or validation under the Cryptographic Module
Validation Program (CMVP) <http://csrc.nist.gov/cryptval/>.  NIST does not accept 
any liability associated with its use or misuse.  This software is provided as-is. 
By accepting this software the user agrees to the terms stated herein.

                            -----------------------

                              Export Restrictions


Implementations of cryptography are subject to United States Federal
Government export controls.  Export controls on commercial encryption products 
are administered by the Bureau of Export Administration (BXA) 
<http://www.bxa.doc.gov/Encryption/> in the U.S. Department of Commerce. 
Regulations governing exports of encryption are found in the Export 
Administration Regulations (EAR), 15 C.F.R. Parts 730-774.
*/


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "rijndael-alg-ref.h"

#include "boxes-ref.dat"

static word8 shifts[4] = {0, 1, 3, 4}; 

word8 mul(word8 a, word8 b) {
   /* multiply two elements of GF(2^m)
    * needed for MixColumn and InvMixColumn
    */
	if (a && b) return Alogtable[(Logtable[a] + Logtable[b])%255];
	else return 0;
}

void TweakAddition(word8 a[4][MAXBC], word8 domain) {
	/* Exor the internal state and the domain seperator (or say tweak) d
	 */
	int i = 0;
	for (i = 0; i < 4; i++)
		a[i][1] ^= domain;
}

void KeyAddition(word8 a[4][MAXBC], word8 rk[4][MAXBC]) {
	/* Exor corresponding text input and round key input bytes
	 */
	int i, j;
	
	for(i = 0; i < 4; i++)
   		for(j = 0; j < BC; j++) a[i][j] ^= rk[i][j];
}

void ShiftRow(word8 a[4][MAXBC]) {
	/* Row 0 remains unchanged
	 * The other three rows are shifted a variable amount
	 */
	word8 tmp[MAXBC];
	int i, j;
	
	for(i = 1; i < 4; i++) {
		for(j = 0; j < BC; j++) tmp[j] = a[i][(j + shifts[i]) % BC];
		for(j = 0; j < BC; j++) a[i][j] = tmp[j];
	}
}

void Substitution(word8 a[4][MAXBC], word8 box[256]) {
	/* Replace every byte of the input by the byte at that place
	 * in the nonlinear S-box
	 */
	int i, j;
	
	for(i = 0; i < 4; i++)
		for(j = 0; j < BC; j++) a[i][j] = box[a[i][j]] ;
}
   
void MixColumn(word8 a[4][MAXBC]) {
        /* Mix the four bytes of every column in a linear way
	 */
	word8 b[4][MAXBC];
	int i, j;
		
	for(j = 0; j < BC; j++)
		for(i = 0; i < 4; i++)
			b[i][j] = mul(2,a[i][j])
				^ mul(3,a[(i + 1) % 4][j])
				^ a[(i + 2) % 4][j]
				^ a[(i + 3) % 4][j];
	for(i = 0; i < 4; i++)
		for(j = 0; j < BC; j++) a[i][j] = b[i][j];
}

int rijndaelKeySched (word8 k[4][MAXKC], word8 W[MAXROUNDS+1][4][MAXBC]) {
	/* Calculate the necessary round keys
	 * The number of calculations depends on keyBits and blockBits
	 */
	int i, j, t, rconpointer = 0;
	word8 tk[4][MAXKC];   

	for(j = 0; j < KC; j++)
		for(i = 0; i < 4; i++)
			tk[i][j] = k[i][j];
	t = 0;
	/* copy values into round key array */
	for(j = 0; (j < KC) && (t < (ROUNDS+1)*BC); j++, t++)
		for(i = 0; i < 4; i++) W[t / BC][i][t % BC] = tk[i][j];
		
	while (t < (ROUNDS+1)*BC) { /* while not enough round key material calculated */
		/* calculate new values */
		for(i = 0; i < 4; i++)
			tk[i][0] ^= S[tk[(i+1)%4][KC-1]];
		tk[0][0] ^= rcon[rconpointer++];

		if (KC != 8)
			for(j = 1; j < KC; j++)
				for(i = 0; i < 4; i++) tk[i][j] ^= tk[i][j-1];

	/* copy values into round key array */
	for(j = 0; (j < KC) && (t < (ROUNDS+1)*BC); j++, t++)
		for(i = 0; i < 4; i++) W[t / BC][i][t % BC] = tk[i][j];
	}		

	return 0;
}
      
int rijndaelEncrypt (word8 a[4][MAXBC], word8 rk[MAXROUNDS+1][4][MAXBC], word8 domain)
{
	/* Encryption of one block. 
	 */
	int i,j,r;
    counter ++;
    if(counter==3){

	/* begin with a key addition
	 */
	KeyAddition(a,rk[0]); 
    //Normal 10 rounds
	for(r = 1; r < ROUNDS-3; r++) {
		TweakAddition(a, domain);
		Substitution(a,S);
		ShiftRow(a);
		MixColumn(a);
		KeyAddition(a,rk[r]);
	}

    word8 a1[4][MAXBC];
    for(i=0;i<4;i++)
        for(j=0;j<8;j++)
                a1[i][j]=a[i][j];
    time_t t;
    srand((unsigned) time(&t));
    int r1=rand()%4;
    int r2=rand()%8;
    int r3=rand()%256;
    a1[r1][r2]^=r3; //Inducing fault at Random position
    //Rounds after fault injection
	for(r = ROUNDS-3; r < ROUNDS; r++) {
		TweakAddition(a, domain);  TweakAddition(a1, domain);
		Substitution(a,S); Substitution(a1,S);
		ShiftRow(a);  ShiftRow(a1);
		MixColumn(a);   MixColumn(a1);
		KeyAddition(a,rk[r]); KeyAddition(a1,rk[r]);
	}
	
	/* Last round is special: there is no MixColumn
	 */
	TweakAddition(a, domain); TweakAddition(a1, domain);
	Substitution(a,S);  Substitution(a1,S);
	ShiftRow(a); ShiftRow(a1);
	KeyAddition(a,rk[ROUNDS]); KeyAddition(a1,rk[ROUNDS]);

    printf("Original Tag T--\n");  //Printing the Original Tag T
    printf("[\n");
    for(i=0;i<4;i++)
		{ 
            printf("[");
       		for(j=0;j<8;j++)
                if(j!=7)
                    printf("0x%02x ,",a[i][j]);
                else
                    printf("0x%02x ",a[i][j]); 
            if(i!=3)
                printf("],\n");
            else
                printf("] \n");
        }
    printf("],\n");
    FILE *fptr;  //writing the Original Tag T to the file final.txt
    fptr = fopen("final.txt", "w");
    if(fptr == NULL)
        {
            printf("Error!");
            exit(1);
        }
   for(i=0;i<4;i++)
       for(j=0;j<8;j++)
           fprintf(fptr,"%d ", a[i][j]);
   fclose(fptr);
   printf("Faulty Tag T'--\n"); //Printing the Faulty Tag T'
   printf("[\n");
   for(i=0;i<4;i++)
	{
        printf("[");
       	for(j=0;j<8;j++)
            if(j!=7)
                printf("0x%02x ,",a1[i][j]);
            else
                printf("0x%02x ",a1[i][j]); 
        if(i!=3)   
			printf("],\n");
        else
            printf("] \n");
    }
   printf("],\n");
   fptr = fopen("final_faulty.txt", "w");//writing the Faulty Tag T' to the file final_faulty.txt
   if(fptr == NULL)
    {
      printf("Error!");
      exit(1);
    }
   for(i=0;i<4;i++)
       for(j=0;j<8;j++)
           fprintf(fptr,"%d ", a1[i][j]);
   fclose(fptr);

   fptr = fopen("key.txt", "w");//writing the last round key in diagonal format to  key.txt
   if(fptr == NULL)
    {
      printf("Error!");
      exit(1);
    }
    printf("The last key in diagonal format--\n"); //Printing the last round key in diagonal format                     
    int shift[]={0,7,5,4};
    printf("( ");
	for(i=0;i<8;i++){
 		for(j=0;j<4;j++){
            if(i==7 && j==3)
                printf("0x%02x \n ),",rk[ROUNDS][j][(i+shift[j])%8]);
            else
                printf("0x%02x,",rk[ROUNDS][j][(i+shift[j])%8]);
            fprintf(fptr,"%d ", rk[ROUNDS][j][(i+shift[j])%8]);
        }
        printf("\n");
    }
    fclose(fptr);

    }
    else
    {
       KeyAddition(a,rk[0]); 

	 
        for(r = 1; r < ROUNDS; r++) {
            TweakAddition(a, domain);
            Substitution(a,S);
            ShiftRow(a);
            MixColumn(a);
            KeyAddition(a,rk[r]);              
            }
	
	/* Last round is special: there is no MixColumn
	 */
       TweakAddition(a, domain); 
       Substitution(a,S);  
       ShiftRow(a); 
	   KeyAddition(a,rk[ROUNDS]); 

    }
                

	return 0;
}



