#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h> 
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <gcrypt.h>

//Returns 1 if the file exists, 0 otherwise.
int file_exists (const char *filename)
{
  FILE *f=NULL;
  if(f=fopen(filename,"r"))
  {
    fclose(f);
    return 1;
  }
  return 0;
}

//Returns the size of file (in bytes).
int getFileSize(FILE* f)
{
    fseek(f, 0, SEEK_END);
    int len = ftell(f);
    rewind(f);
    return len;
}

//Generates the key using PBKDF2 and stores it in a variable named "key". Returns 1, if successful, else 0.
int generateKey(const char* passphrase, unsigned char* key)
{
	if(!gcry_kdf_derive (passphrase,strlen(passphrase),GCRY_KDF_PBKDF2,GCRY_MD_SHA512,"NaCl",4,4096,16,key))
		return 1;
	else
		return 0;
}

//Encrypts the data present in 'ptxt' and stores the encrypted contents using 'p_ctxt'. Returns the padding required to make the encryption routine work - it only works when the input size is a multiple of block length (in this case - it's 16).
int encrypt(const unsigned char* key, const char * passphrase, const char* ptxt, unsigned char** p_ctxt,const size_t len, int* ctxtLen)
{
	if (key)
	{
		int index=0,pad=0;
		printf("Key: ");
		while(index<16) printf("%2x ",*(key+index++));	//print key (in hex)
		printf("\n");

		gcry_cipher_hd_t handle;
		gcry_error_t err=0;

		err=gcry_cipher_open (&handle,GCRY_CIPHER_AES128,GCRY_CIPHER_MODE_CBC,0); //open handle
		if(!err)
		{
			unsigned int IV[]={0,0,0,5844};
			err=gcry_cipher_setkey (handle,key,16); //set key
			if(!err)
			{
				
				// compute the padding required
				if(len%16==0) pad=16;
				else while((len+pad)%16!=0) pad++;

				*p_ctxt=calloc(len+pad,sizeof(char)); // this is where CTXT will be stored

				if(*p_ctxt)
				{
					char* temp=calloc(len+pad,sizeof(char)); // will contain [PTXT + pad bytes]
					memcpy(temp,ptxt,len+pad);

					err=gcry_cipher_setiv (handle,&IV,16); //set IV
					if(!err)
					{	err=gcry_cipher_encrypt (handle,*p_ctxt,len+pad,temp,len+pad); //encrypt
						*ctxtLen=len+pad; // save the total length of ciphertext (in *ctxtLen)

						if (err) 
								printf("Could not encrypt! -- %s\n",gcry_strerror(err));
						free(temp);
					}
					else
						printf("Could not set IV for encryption routine! -- %s\n",gcry_strerror(err));
				}
				else
					printf("Could not allocate space for ciphertext!\n");
			}
			else
				printf("Could not set key for encryption routine! -- %s\n",gcry_strerror(err));

			gcry_cipher_close (handle);	
		}
		else
			printf("Could not open handle for encryption routine! -- %s\n",gcry_strerror(err));

		return pad;
	}
}

//Decrypts the data present in 'ctxt' and stores decrypted contents using 'p_dtxt'. 
void decrypt(const unsigned char* key, const char * passphrase, const unsigned char* ctxt, unsigned char** p_dtxt, const int pad, const size_t len)
{
	if (key)
	{
			int index=0;
			printf("Key: ");
			while(index<16) printf("%2x ",*(key+index++));	//print key (in hex)
			printf("\n");

			gcry_cipher_hd_t handle;
			gcry_error_t err=0;

			err=gcry_cipher_open (&handle,GCRY_CIPHER_AES128,GCRY_CIPHER_MODE_CBC,0); //open handle
			if(!err)
			{
				unsigned int IV[]={0,0,0,5844};
				err=gcry_cipher_setkey (handle,key,16); //set key
				if(!err)
				{
					*p_dtxt=calloc(len,sizeof(char)); //will hold decrypted-TXT (== (PTXT + Pad bytes))

					if (*p_dtxt)
					{
						err=gcry_cipher_setiv (handle,&IV,16);  //set IV
						if(!err)
						{	
							err=gcry_cipher_decrypt (handle,*p_dtxt,len,ctxt,len); //decrypt

							if (err) 
								printf("Could not decrypt! -- %s\n",gcry_strerror(err));
						}
						else
							printf("Could not set IV for decryption routine! -- %s\n",gcry_strerror(err));
					}
					else
						printf("Could not allocate space for plaintext!\n");
				}
				else
					printf("Could not set key for decryption routine! -- %s\n",gcry_strerror(err));

				gcry_cipher_close (handle);	
			}
			else
				printf("Could not open handle for decryption routine! -- %s\n",gcry_strerror(err));
	}
}

//Computes the MAC of 'src' and stores it in 'dest'.
void getMAC(const char* src, const size_t src_len, unsigned char* dest, const char* key, const size_t keySize)
{
	gcry_md_hd_t digest = NULL;
	gcry_error_t err=0;

	err = gcry_md_open(&digest, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
    if (err)
        printf("Could not open handle for HMAC! -- %s\n",gcry_strerror(err));
    else
    {
    	err = gcry_md_setkey(digest,key,keySize);
	    if (err)
	        printf("Could not set key for HMAC! -- %s\n",gcry_strerror(err));
	    else
	    {
	    	int i=0;
	    	while(i<src_len) gcry_md_write(digest,(src+i++),1);
	    	memcpy(dest,gcry_md_read(digest, 0),64);
		}

		gcry_md_close(digest);
	}
}


#if 0
//For debugging purposes
void printHex(const char* name,const unsigned char* x,const size_t y)
{
	if (name && x)
	{
		int i=0;
		printf("%s = ",name);
		while(i<y)printf("%x ",*(x+i++));
		printf("\n");
	}
}


void printChar(const char* name,const unsigned char* x,const size_t y)
{
	if (name && x)
	{
		int i=0;
		printf("%s = ",name);
		while(i<y)printf("%c ",*(x+i++));
		printf("\n");
	}
}
#endif