#include "header.h"

int main(int argc, char *argv[])
{
    // techrypt < input file > [-d < IP-addr:port >][-l ]

    if((argc==4) && strncmp(*(argv+2),"-d",2)==0) //for sending file over network
    {
        char IP[16];
        char port[6];
        memset(IP,0,16);
        memset(port,0,6);
        
        char *token=NULL;
        int i=0;

        if (strchr(*(argv+3),':')) //check if port number has been provided
        {
            int sockfd = 0;
            struct sockaddr_in serv_addr; 
            
            FILE *f=fopen(*(argv+1),"r");
            int c=0,index=0,fLen=getFileSize(f);
            
            char fileContents[fLen];
            memset(fileContents,0,fLen);
            while((c=fgetc(f)) && !feof(f)) *(fileContents+index++)=c; //read file's contents into a buffer : 'fileContents'
            fclose(f);

            char passphrase[30];
            printf("Password: ");
            gets(passphrase); // get password

            unsigned char key[16];
            memset(key,0,16);
            
            unsigned char *ctxt=NULL;
            unsigned char **p_ctxt=&ctxt;
            
            unsigned char mac[64];
            memset(mac,0,64);

            if(generateKey(passphrase,key)) //generate key and store it in buffer named 'key'
            {
                int pad=0;
                int ctxtLen=0;

                pad=encrypt(key,passphrase,fileContents,p_ctxt,fLen,&ctxtLen); //encrypt PTXT

                if(ctxt)
                {
                    getMAC(ctxt,ctxtLen,mac,key,16); //get MAC for generated PTXT and store its value in variable named 'mac'

                    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
                    {
                        printf("\nCould not create socket!\n");
                        return 1;
                    } 

                    memset(&serv_addr, '0', sizeof(serv_addr)); 

                    serv_addr.sin_family = AF_INET;

                    char IPAddress[22];
                    memset(IPAddress,0,22);
                    strncpy(IPAddress,*(argv+3),21);
                    
                    for(token=strtok(*(argv+3),":");token!=NULL;token=strtok(NULL,":"),i++)
                    {
                        if (i==0) strncpy(IP,token,15); //get IP
                        else strncpy(port,token,5); //get port number
                    }

                    serv_addr.sin_port = htons(atoi(port)); 

                    if(inet_pton(AF_INET, IP, &serv_addr.sin_addr)<=0)
                    {
                        printf("\n'inet_pton' Error!\n");
                        return 1;
                    } 

                    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
                    {
                       printf("\nConnection Failed!\n");
                       return 1;
                    } 
                    printf("Transmitting to %s.\n",IPAddress);

                    char fNameLen[20];
                    memset(fNameLen,0,20);
                    sprintf(fNameLen,"%zu",strlen(*(argv+1))); //store file-name's length in variable 'fNameLen'

                    char fLength[20];
                    memset(fLength,0,20);
                    sprintf(fLength,"%d",ctxtLen+64); //store file's length in variable 'fLength'

                    char padASCII[20];
                    memset(padASCII,0,20);
                    sprintf(padASCII,"%d",pad); //store pad in variable 'padASCII'

                    char padLen[20];
                    memset(padLen,0,20);
                    sprintf(padLen,"%zu",strlen(padASCII)); //store pad's length in variable 'padLen'

                    write(sockfd,fNameLen,strlen(fNameLen)); //send file name's length
                    write(sockfd,*(argv+1),strlen(*(argv+1))); //send file's name
                    write(sockfd,padLen,strlen(padLen)); //send pad length
                    write(sockfd,"-",1); // send delimiter
                    write(sockfd,padASCII,strlen(padASCII)); //send pad
                    write(sockfd,fLength,strlen(fLength)); // send encrypted file's length
                    write(sockfd,ctxt,ctxtLen); // send encrypted file's contents
                    write(sockfd,mac,64); // send mac

                    printf("Successfully sent.\n");

                    if(ctxt)
                        free(ctxt);

                    return 0;
                }
                else
                    return 1;
            }
            else
            {
                printf("Error incurred during key generation!\n");
                return 1;
            }
        }
        else
        {
            printf("Invalid address!\n");
            return 1;
        }
    }
    if((argc==3) && strncmp(*(argv+2),"-l",2)==0) //for 'local' operation
    {
            char newFileName[strlen(*(argv+1))+3];
            memset(newFileName,0,strlen(*(argv+1))+3);

            strcpy(newFileName,*(argv+1));
            strcat(newFileName,".gt");

            if(!file_exists(newFileName)) // if file with name 'newFileName' exists, return 33
            {
                    FILE *f=fopen(*(argv+1),"r");
                    int c=0,index=0,fLen=getFileSize(f);
                    
                    char fileContents[fLen];
                    memset(fileContents,0,fLen);
                    while((c=fgetc(f)) && !feof(f)) *(fileContents+index++)=c; // read the contents of file (to be encrypted)
                    fclose(f);

                    char passphrase[30];
                    printf("Password: ");
                    gets(passphrase); // get password

                    unsigned char key[16];
                    memset(key,0,16);

                    unsigned char *ctxt=NULL;
                    unsigned char** p_ctxt=&ctxt;

                    unsigned char mac[64];
                    memset(mac,0,64);

                    if(generateKey(passphrase,key)) //generate key and store in the buffer named 'key
                    {   
                        int pad=0;

                        int ctxtLen=0;

                        pad=encrypt(key,passphrase,fileContents,p_ctxt,fLen,&ctxtLen);  //encrypt PTXT

                        if(ctxt)
                        {
                            getMAC(ctxt,ctxtLen,mac,key,16); //get MAC for generated PTXT and store its value in the variable named 'mac'

                            char padASCII[20];
                            memset(padASCII,0,20);
                            sprintf(padASCII,"%d",pad); //store pad's value in variable "pad"

                            FILE *f=fopen(newFileName,"w");
                            
                            fprintf(f,"%zu",strlen(padASCII));// write padLen
                            fprintf(f,"%c",'-'); // write delimiter
                            fprintf(f,"%d",pad); // write pad

                            index=0;
                            while(index<ctxtLen) fputc(*(ctxt+index++),f); // write encrypted file's contents

                            index=0;
                            while(index<64) fputc(*(mac+index++),f); // write mac
                            fclose(f);

                            if(ctxt)
                                free(ctxt);

                            return 0;
                        }
                        else
                            return 1;
                    }
                    else
                        return 1;
            }
            else
                return 33;
    }
    else
    {
        printf("Invalid option(s) given!\n");
        return 1;
    }
}