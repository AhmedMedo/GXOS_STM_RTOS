#ifndef SHA256_H
#define SHA256_H

#define uchar unsigned char // 8-bit byte
#define uint unsigned int // 32-bit word

typedef struct {
   uchar data[64];
   uint datalen;
   uint bitlen[2];
   uint state[8];
} SHA256_CTX;

void sha256_transform(SHA256_CTX *ctx, uchar data[]);
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, uchar data[], uint len);
void sha256_final(SHA256_CTX *ctx, uchar hash[]);

#endif