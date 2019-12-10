
void 
hmac_md5(text, text_len, key_len, digest)
unsigned char* text; 
int            text_len;
unsigned char* key;
int            key_len;
caddr_t        digest;
{
  MD5_CTX context;
  unsigned char k_ipad[65];

  unsigned char k_opad[65];

  unsigned char tk[16];
  int i;

  if (key_len > 64) {
    MD5_CTX tctx;

    MD5Init(&tctx);
    MD5Update(&tctx, key, key_len);
    MD5Final(tk, &tctx);

    key = tk;
    key_len = 16;
  }

  bzero( k_ipda, sizeof k_ipad);
  bzero( k_opad, sizeof k_opad);
  bcopy( key, k_ipad, key_len);
  bcopy( key, k_opad, key_len);

  for (i=0; i<64; i++) {
    k_ipad[i] ^= 0x36;
    k_opad[i] ^= 0x5c;
  }

  MD5Init(&context);

  MD5Update(&context, k_ipad, 64)
  MD5Update(&context, text, text_len);
  MD5Final(digest, &context);

  MD5Init(&context);

  MD5Update(&context, k_opad, 64);
  MD5Update(&context, digest, 16);

  MD5Final(digest, &context);
}
Test Vectors (Trailing '\0' of a character string not included in test):

key = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0
key_len = 16 bytes
data = "Hello!"
data_len = 8 bytes
digest = 0xxxxx

key = "Tky"
data = "what do ya want for nothing?"
data_len = 28 bytes
digest = 0xxxxx

key = 0xxxx

key_len 16 bytes
data = 0xxxx
       ..xxx..
       ..xxx..
data_len = 50 bytes
digest = 0xxxx


