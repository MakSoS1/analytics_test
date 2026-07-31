#define _GNU_SOURCE
#include <openssl/aes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <omp.h>

static const char *codes[] = {
    "387D","DDED","A6EE","918A","10FA","10F6","BFCC","F5A9",
    "E8E1","D2FA","A890","1022","2222","F92D","EAFE","7E81",
    "CAFE","9168","DB92","DEB9"
};
#define N ((int)(sizeof(codes)/sizeof(codes[0])))

static int hexv(char c){ return (c>='0'&&c<='9') ? c-'0' : c-'A'+10; }
static int printable16(const unsigned char *p){
    int c=0;
    for(int i=0;i<16;i++) if((p[i]>=32&&p[i]<=126)||p[i]=='\n'||p[i]=='\r'||p[i]=='\t') c++;
    return c>=13;
}
static int all_text(const unsigned char *p,int n){
    for(int i=0;i<n;i++) if(!((p[i]>=32&&p[i]<=126)||p[i]=='\n'||p[i]=='\r'||p[i]=='\t')) return 0;
    return 1;
}
int main(int argc,char **argv){
    if(argc!=4){fprintf(stderr,"usage: solver shard ciphertext output\n");return 64;}
    int shard=atoi(argv[1]); if(shard<0||shard>=N) return 65;
    FILE *f=fopen(argv[2],"rb"); if(!f) return 66;
    unsigned char ct[4096]; size_t len=fread(ct,1,sizeof(ct),f); fclose(f);
    if(len<16 || len%16) return 67;
    unsigned char cb[N][2];
    for(int z=0;z<N;z++){
        cb[z][0]=(hexv(codes[z][0])<<4)|hexv(codes[z][1]);
        cb[z][1]=(hexv(codes[z][2])<<4)|hexv(codes[z][3]);
    }
    volatile int found=0;
    #pragma omp parallel for schedule(dynamic,1)
    for(int b=0;b<N;b++) if(b!=shard)
    for(int c=0;c<N;c++) if(c!=shard&&c!=b)
    for(int d=0;d<N;d++) if(d!=shard&&d!=b&&d!=c)
    for(int e=0;e<N;e++) if(e!=shard&&e!=b&&e!=c&&e!=d)
    for(int g=0;g<N;g++) if(g!=shard&&g!=b&&g!=c&&g!=d&&g!=e)
    for(int h=0;h<N;h++) if(h!=shard&&h!=b&&h!=c&&h!=d&&h!=e&&h!=g)
    for(int i=0;i<N;i++) if(i!=shard&&i!=b&&i!=c&&i!=d&&i!=e&&i!=g&&i!=h){
        if(found) continue;
        int idx[8]={shard,b,c,d,e,g,h,i};
        unsigned char key[16];
        for(int k=0;k<8;k++){ key[2*k]=cb[idx[k]][0]; key[2*k+1]=cb[idx[k]][1]; }
        AES_KEY ks; AES_set_decrypt_key(key,128,&ks);
        unsigned char last[16]; AES_decrypt(ct+len-16,last,&ks);
        int pad=last[15]; if(pad<1||pad>16) continue;
        int ok=1; for(int k=16-pad;k<16;k++) if(last[k]!=(unsigned char)pad){ok=0;break;} if(!ok) continue;
        unsigned char first[16]; AES_decrypt(ct,first,&ks); if(!printable16(first)) continue;
        unsigned char pt[4096];
        for(size_t off=0;off<len;off+=16) AES_decrypt(ct+off,pt+off,&ks);
        int plen=(int)len-pad;
        unsigned char *flag=(unsigned char*)memmem(pt,plen,"bushbash{",9);
        if(!flag && !all_text(pt,plen)) continue;
        #pragma omp critical
        {
            if(!found){
                found=1;
                FILE *o=fopen(argv[3],"wb");
                if(o){
                    if(flag){
                        unsigned char *end=memchr(flag,'}',(pt+plen)-flag);
                        if(end) fwrite(flag,1,(size_t)(end-flag+1),o);
                        else fwrite(pt,1,plen,o);
                    } else fwrite(pt,1,plen,o);
                    fclose(o);
                }
            }
        }
    }
    return found?0:1;
}
