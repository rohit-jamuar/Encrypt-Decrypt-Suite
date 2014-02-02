#include "header.h"

#define DEFAULTFILESIZE 1024

int main(int argc, char *argv[])
{   
    // techdec -d < port >

    if ((argc==3) && strncmp(*(argv+1),"-d",2)==0) //for receiving file over network
    {
        int listenfd = 0, connfd = 0, retVal=0, contentLen=0;
        struct sockaddr_in serv_addr; 
        char *buffer=NULL;
        char *fName=NULL;

        listenfd = socket(AF_INET, SOCK_STREAM,0);
        memset(&serv_addr,0, sizeof(serv_addr));

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        serv_addr.sin_port = htons(atoi(*(argv+2))); 

        bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)); 

        listen(listenfd, 5); 

        printf ("Waiting for connections.\n");

        connfd = accept(listenfd, (struct sockaddr*)NULL, NULL); 

        printf("Inbound file.\n");

        int index=0;

        if (buffer=calloc(DEFAULTFILESIZE,sizeof(char)))
        {
            int ch=0,curSize=2,padLen=0;

            read(connfd,&ch,1);

            char fNameLen[50];
            memset(fNameLen,0,50);
            int i=0;
            while(ch!=0 && isdigit(ch)) //read file-name's length
            {
                *(fNameLen+i++)=ch;
                read(connfd,&ch,1);
            }

            fName=calloc(atoi(fNameLen),sizeof(char));
            
            int pos=0;
            contentLen=atoi(fNameLen);
            while(pos<contentLen) //read file-name
            {
                *(fName+pos++)=ch;
                read(connfd,&ch,1);
            }

            if(!file_exists(fName))
            {
                char padLen[20];
                memset(padLen,0,20);
                i=0;
                while(ch!=0) //get pad's length
                {
                    if (ch=='-')
                    {
                        read(connfd,&ch,1);   //move a character away from '-' 
                        break;
                    }
                    *(padLen+i++)=ch;
                    read(connfd,&ch,1);
                }

                char padASCII[20];
                memset(padASCII,0,20);
                contentLen=atoi(padLen);
                i=0;
                while(i<contentLen) //get pad
                {
                    *(padASCII+i++)=ch;
                    read(connfd,&ch,1);
                }

                char fContentLen[50];
                memset(fContentLen,0,50);
                i=0;
                while(ch!=0 && isdigit(ch)) //get file-content's length
                {
                   *(fContentLen+i++)=ch;
                    read(connfd,&ch,1);
                }

                index=0;
                contentLen=atoi(fContentLen);
                while(index<contentLen) //get file (encrypted file + MAC(encrypted file))
                {
                    if(index>=DEFAULTFILESIZE) //for resizing 'buffer', as and when needed
                        buffer=realloc(buffer,DEFAULTFILESIZE*curSize++);
                    if (buffer)
                    {
                        *(buffer+index++)=ch;
                        read(connfd,&ch,1);    
                    }
                    else
                    {
                        printf ("Error incurred during expansion of buffer space.\n!");
                        retVal=1;
                    }
                }
                if (index>0 && ((buffer=realloc(buffer,index))==NULL) && !retVal)
                {
                    printf("Error resizing buffer.\n!");
                    retVal=1;
                }

                if (!retVal)
                {
                    unsigned char ctxtReceived[index-64]; 
                    memcpy(ctxtReceived,buffer,index-64); //extract CTXT from buffer

                    unsigned char macReceived[64];
                    memcpy(macReceived,buffer+(index-64),64); //extract MAC from buffer

                    unsigned char macGenerated[64];
                    
                    char passphrase[30];
                    printf("Password: ");
                    gets(passphrase);

                    unsigned char key[16];
                    memset(key,0,16);
                    
                    if(generateKey(passphrase,key)) //generate key and store in buffer named 'key'
                    {
                        getMAC(ctxtReceived,index-64,macGenerated,key,16); //get MAC for received-CTXT and store the value in variable named 'macGenerated'
                        
                        if (memcmp(macReceived,macGenerated,64)!=0) //check MACs
                        {
                            printf("Wrong MAC!\n");
                            retVal=62;
                        }
                            
                        else
                        {
                            unsigned char *ptxt=NULL;
                            unsigned char **p_ptxt=&ptxt;

                            decrypt(key,passphrase,ctxtReceived,p_ptxt,atoi(padASCII),index-64); //decrypt CTXT and store the decrypted text in variable named 'ptxt'

                            FILE* f=fopen(fName,"w");
                            if (f)
                            {
                                if(ptxt)
                                {
                                    int pos=0;
                                    int contentLength=index-64-atoi(padASCII); //index = net length of file read, 64 = number of bytes of MAC, atoi(padASCII) = pad appended and encrypted along with PTXT.
                                    while(pos<contentLength) fputc(*(ptxt+pos++),f); //store the generated PTXT

                                    free(ptxt);
                                    printf("Successfully received and decrypted %s (%d bytes written).\n",fName,contentLength);
                                    retVal=0;
                                }
                                else
                                    retVal=1;
                                fclose(f);
                            }
                            else
                            {
                                printf("Could not create a new file!\n");
                                retVal=1;
                            }
                        }
                    }
                    else
                    {
                        printf("Error incurred during key generation!\n");
                        retVal=1;
                    }
                }
            }
            else
            {
                printf("This file has already been received!!!\n");
                retVal=33;
            }
        
            if (buffer)
                free(buffer);
            if (fName)
                free(fName);

            close(connfd);
            return retVal;
        }
        else
        {
            printf("Could not allocate memory to store file's content!\n");
            return 1;
        }
    }

    if ((argc==3) && strncmp(*(argv+2),"-l",2)==0) //for decryption in 'local' mode
    {
        // techdec < filename >  [-l]
        int retVal=0, ch=0, contentLen=0;

        char fNameNew[strlen(*(argv+1))-3]; // -3 for removing ".gt"
        strncpy(fNameNew,*(argv+1),strlen(*(argv+1))-3);

        if (!file_exists(fNameNew))
        {
            FILE* f=fopen(*(argv+1),"r");
            if (f)
            {   
                int i=0, ch=0;
                int fLen=getFileSize(f);

                char padLen[20];
                memset(padLen,0,20);
                while((ch=fgetc(f)) && (ch!='-' && ch!=EOF)) *(padLen+i++)=ch; //get pad's length

                char padASCII[20];
                memset(padASCII,0,20);
                i=0;
                while((ch=fgetc(f)) && (i<atoi(padLen))) *(padASCII+i++)=ch; //get pad

                int pad=atoi(padASCII);

                unsigned char buffer[fLen-strlen(padLen)-strlen(padASCII)-1];
                memset(buffer,0,fLen-strlen(padLen)-strlen(padASCII)-1);

                i=0;
                while(ch!=EOF) //read the (encrypted) contents of file into 'buffer'
                {
                    *(buffer+i++)=ch;
                    ch=fgetc(f);
                }

                fclose(f);

                unsigned char ctxtRead[i-64];
                memset(ctxtRead,0,i-64);
                memcpy(ctxtRead,buffer,i-64); //extract CTXT from 'buffer'

                unsigned char macRead[64];
                memset(macRead,0,64);
                memcpy(macRead,buffer+i-64,64); //extract MAC value from 'buffer'

                unsigned char macGenerated[64];
                    
                char passphrase[30];
                printf("Password: ");
                gets(passphrase); //get password

                unsigned char key[16];
                memset(key,0,16);
                
                if(generateKey(passphrase,key)) //generate key and store in buffer named 'key'
                {
                    getMAC(ctxtRead,i-64,macGenerated,key,16); //get MAC for received-CTXT and store the value in variable named 'macGenerated'

                    if (memcmp(macRead,macGenerated,64)!=0) //check MACs
                    {
                        printf("Wrong MAC!\n");
                        retVal=62;
                    }
                    else
                    {
                        unsigned char *ptxt=NULL;
                        unsigned char **p_ptxt=&ptxt;

                        decrypt(key,passphrase,ctxtRead,p_ptxt,pad,i-64); //decrypt CTXT and store the decrypted text in variable named 'ptxt'

                        FILE* f=fopen(fNameNew,"w");
                        if (f)
                        {
                            if (ptxt)
                            {
                                int pos=0;
                                while(pos<(i-64-pad)) fputc(*(ptxt+pos++),f); //i = net length of file read, 64 = number of bytes of MAC, pad = pad appended and encrypted along with PTXT.
                               
                                printf("Successfully decrypted %s (%d bytes written).\n",*(argv+1),i-64-pad);
                                retVal=0;
                                free(ptxt);
                            }
                            else
                                retVal=1;
                            fclose(f);
                        }
                        else
                        {
                            printf("Could not create a new file!\n");
                            retVal=1;
                        }
                    }
                }
                else
                {
                    printf("Error incurred during key generation!\n");
                    retVal=1;
                }
            }
            else
            {
                printf("Could not open file!\n");
                retVal=1;
            }
        }
        else
        {
            printf("This file has already been received!!!\n");
            retVal=33;
        }
        return retVal;
    }   
    else
    {
        printf("Improper number of options entered!\n");
        return 1;  
    }
}

     
