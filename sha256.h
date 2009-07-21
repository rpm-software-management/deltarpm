/*
 * This software is in the public domain as per
 * http://archives.neohapsis.com/archives/crypto/2000-q4/0730.html
 * Changes by Jonathan Dieter are also in the public domain
 */

#if !defined( _sha256_h )
#define _sha256_h

typedef struct {
      unsigned int H[ 8 ];
      unsigned int hbits, lbits;
      unsigned char M[ 64 ];
      unsigned int mlen;
} SHA256_ctx;

void SHA256_init ( SHA256_ctx *ctx);
void SHA256_update( SHA256_ctx *ctx, const unsigned char *data, unsigned int length );
void SHA256_final ( SHA256_ctx *ctx);
void SHA256_digest( SHA256_ctx *ctx, unsigned char *digest);

#endif
