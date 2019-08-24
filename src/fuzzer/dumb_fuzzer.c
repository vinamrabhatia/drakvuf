#include <stdlib.h>
#include <stdio.h>

unsigned long rand_uint64_slow() {
        unsigned long r = 0;
        for (int i=0; i<64; i++) {
                r = r*2 + rand()%2;
        }
        return r;
}

unsigned char rand_uint8_slow() {
        unsigned char r = 0;
        for (int i=0; i<8; i++) {
                r = r*2 + rand()%2;
        }
        return r;
}

int main(int  argc, char* argv[])
{
        int  n =  atoi(argv[1]);
        for(int j=0; j<n; j++)
        {
                for(int i=2; i<argc; i++)
                {
                        if(*argv[i] == 'i')
                        {
                                printf("i %lu ", rand_uint64_slow());
                        }
                        else if(*argv[i] == 's')
                        {
                                unsigned long len = rand_uint64_slow()%16;
                                printf("s ");
                                for(unsigned int k=0; k<len;k++)
                                {
                                        printf("%x",rand_uint8_slow());
                                }
                                printf(" ");
                        }
                }
                printf("\n");
        }
}
