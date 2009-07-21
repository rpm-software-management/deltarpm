typedef unsigned int uint32;

struct MD5Context {
        uint32 buf[4];
        uint32 bits[2];
        unsigned char in[64];
        int doByteReverse;
};
typedef struct MD5Context MD5_CTX;

void rpmMD5Init(struct MD5Context *context);
void rpmMD5Update(struct MD5Context *context, unsigned char const *buf, unsigned len);
void rpmMD5Update32(struct MD5Context *context, unsigned int i);
void rpmMD5Final(unsigned char digest[16], struct MD5Context *context);
