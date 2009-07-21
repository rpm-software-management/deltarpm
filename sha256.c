/*
 * Implementation of SHA-256, based on Adam Back's sha-1 implementation.
 * This software is in the public domain as per
 * http://archives.neohapsis.com/archives/crypto/2000-q4/0730.html
 * Changes by Jonathan Dieter are also in the public domain
 */

#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "sha256.h"

#define min( x, y ) ( ( x ) < ( y ) ? ( x ) : ( y ) )

#define S(x,n) ( ((x)>>(n)) | ((x)<<(32-(n))) )
#define R(x,n) ( (x)>>(n) )

#define Ch(x,y,z) ( ((x) & (y)) | (~(x) & (z)) )
#define Maj(x,y,z) ( ( (x) & (y) ) | ( (x) & (z) ) | ( (y) & (z) ) )

#define SIG0(x) ( S(x, 2) ^ S(x,13) ^ S(x,22) )
#define SIG1(x) ( S(x, 6) ^ S(x,11) ^ S(x,25) )
#define sig0(x) ( S(x, 7) ^ S(x,18) ^ R(x, 3) )
#define sig1(x) ( S(x,17) ^ S(x,19) ^ R(x,10) )

static unsigned int K[] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define H1 0x6a09e667
#define H2 0xbb67ae85
#define H3 0x3c6ef372
#define H4 0xa54ff53a
#define H5 0x510e527f
#define H6 0x9b05688c
#define H7 0x1f83d9ab
#define H8 0x5be0cd19

unsigned int H[ 8 ] = { H1, H2, H3, H4, H5, H6, H7, H8 };

/* convert to big endian where needed */

static void convert_to_bigendian( void *data, int len )
{
/* test endianness */
   unsigned int test_value = 0x01;
   unsigned char *test_as_bytes = (unsigned char*) &test_value;
   int little_endian = test_as_bytes[ 0 ];

   unsigned int temp;
   unsigned char *temp_as_bytes = (unsigned char*) &temp;
   unsigned int *data_as_words = (unsigned int*) data;
   unsigned char *data_as_bytes;
   int i;

   if ( little_endian )
   {
      len /= 4;
      for ( i = 0; i < len; i++ )
      {
         temp = data_as_words[ i ];
         data_as_bytes = (unsigned char*) &( data_as_words[ i ] );
         
         data_as_bytes[ 0 ] = temp_as_bytes[ 3 ];
         data_as_bytes[ 1 ] = temp_as_bytes[ 2 ];
         data_as_bytes[ 2 ] = temp_as_bytes[ 1 ];
         data_as_bytes[ 3 ] = temp_as_bytes[ 0 ];
      }
   }

/* on big endian machines do nothing as the CPU representation
 *    automatically does the right thing for SHA1 */
}

void SHA256_init( SHA256_ctx* ctx )
{
   memcpy( ctx->H, H, 8 * sizeof( unsigned int ) );
   ctx->lbits = 0;
   ctx->hbits = 0;
   ctx->mlen = 0;
}

static void SHA256_transform( SHA256_ctx* ctx )
{
   int t;
   unsigned int A = ctx->H[ 0 ];
   unsigned int B = ctx->H[ 1 ];
   unsigned int C = ctx->H[ 2 ];
   unsigned int D = ctx->H[ 3 ];
   unsigned int E = ctx->H[ 4 ];
   unsigned int F = ctx->H[ 5 ];
   unsigned int G = ctx->H[ 6 ];
   unsigned int H = ctx->H[ 7 ];
   unsigned int T1, T2;
   unsigned int W[ 64 ];

   memcpy( W, ctx->M, 64 );

   for ( t = 16; t < 64; t++ )
   {
      W[ t ] = sig1(W[t-2]) + W[t-7] + sig0(W[t-15]) + W[t-16];
   }

   for ( t = 0; t < 64; t++ )
   {
      T1 = H + SIG1(E) + Ch(E,F,G) + K[t] + W[t];
      T2 = SIG0(A) + Maj(A,B,C);
      H = G;
      G = F;
      F = E;
      E = D + T1;
      D = C;
      C = B;
      B = A;
      A = T1 + T2;
   }


   ctx->H[ 0 ] += A;
   ctx->H[ 1 ] += B;
   ctx->H[ 2 ] += C;
   ctx->H[ 3 ] += D;
   ctx->H[ 4 ] += E;
   ctx->H[ 5 ] += F;
   ctx->H[ 6 ] += G;
   ctx->H[ 7 ] += H;
}

void SHA256_update( SHA256_ctx* ctx, const unsigned char *data, unsigned int length)
{
   unsigned int use;
   unsigned int low_bits;
   
/* convert length to bits and add to the 64 bit word formed by lbits
 *    and hbits */

   ctx->hbits += length >> 29;
   low_bits = length << 3;
   ctx->lbits += low_bits;
   if ( ctx->lbits < low_bits ) { ctx->hbits++; }

/* deal with first block */

   use = min( 64 - ctx->mlen, length );
   memcpy( ctx->M + ctx->mlen, data, use );
   ctx->mlen += use;
   length -= use;
   data += use;

   while ( ctx->mlen == 64 )
   {
      convert_to_bigendian( (unsigned int*)ctx->M, 64 );
      SHA256_transform( ctx );
      use = min( 64, length );
      memcpy( ctx->M, data, use );
      ctx->mlen = use;
      length -= use;
      data += use; /* was missing */
   }
}

void SHA256_final( SHA256_ctx* ctx )
{
   if ( ctx->mlen < 56 )
   {
      ctx->M[ ctx->mlen ] = 0x80; ctx->mlen++;
      memset( ctx->M + ctx->mlen, 0x00, 56 - ctx->mlen );
      convert_to_bigendian( ctx->M, 56 );
   }
   else
   {
      ctx->M[ ctx->mlen ] = 0x80;
      ctx->mlen++;
      memset( ctx->M + ctx->mlen, 0x00, 64 - ctx->mlen );
      convert_to_bigendian( ctx->M, 64 );
      SHA256_transform( ctx );
      memset( ctx->M, 0x00, 56 );
   }

   memcpy( ctx->M + 56, (void*)(&(ctx->hbits)), 8 );
   SHA256_transform( ctx );
}

void SHA256_digest( SHA256_ctx* ctx, unsigned char *digest )
{
   if ( digest )
   {
      memcpy( digest, ctx->H, 8 * sizeof( unsigned int ) );
      convert_to_bigendian( digest, 8 * sizeof( unsigned int ) );
   }
}

void SHA256_update32( SHA256_ctx* ctx, unsigned int i)
{
   unsigned char d[4];
   d[0] = i >> 24;
   d[1] = i >> 16;
   d[2] = i >> 8;
   d[3] = i;
   SHA256_update(ctx, d, 4);
}
