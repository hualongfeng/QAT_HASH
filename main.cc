#include <iostream>
#include "crypto.h"
#include <pthread.h>
#include <thread>
#include <string.h>
#include <vector>

using namespace std;


unsigned char sha256result4M[] = {
  0x0b, 0xf0, 0xbe, 0xc7,
  0x58, 0xd8, 0x86, 0x13,
  0xcc, 0xc6, 0xb4, 0xc7,
  0xa1, 0xc1, 0x6e, 0x4c,
  0x87, 0x63, 0xaa, 0x18,
  0x22, 0x93, 0x33, 0xde,
  0x87, 0x4c, 0x71, 0x93,
  0x77, 0xcd, 0xed, 0x64
};

unsigned char md5result4M[] = {
  0xd8, 0x35, 0xde, 0x17,
  0x69, 0xad, 0x8d, 0x1b,
  0x2d, 0x35, 0xda, 0xf6,
  0x40, 0x03, 0xcb, 0x04
};


/**
 ********************************************************************************
 * @ingroup sampleUtils
 *      This function and associated macro sleeps for ms milliseconds
 *
 * @param[in] ms    sleep time in ms
 *
 * @retval none
 *
 *******************************************************************************/
static __inline CpaStatus sampleSleep(Cpa32U ms)
{
  int ret = 0;
  struct timespec resTime, remTime;
  resTime.tv_sec = ms / 1000;
  resTime.tv_nsec = (ms % 1000) * 1000000;
  do
  {
    ret = nanosleep(&resTime, &remTime);
    resTime = remTime;
  } while ((ret != 0) && (errno == EINTR));

  if (ret != 0)
  {
    std::cout << "nanoSleep failed with code "<< ret << std::endl;
    return CPA_STATUS_FAIL;
  }
  else
  {
    return CPA_STATUS_SUCCESS;
  }
}


#define OS_SLEEP(ms) sampleSleep((ms))

void testSHA256();
void testMD5();

int main() {
  std::cout << "This is main!!!" << std::endl;
  std::cout << "--------------------" << std::endl;
for (int i = 0; i < 10000; i++) {
  std::thread first(testSHA256);
  std::thread second(testSHA256);
  std::thread three(testMD5);
  std::thread four(testMD5);
  std::thread five(testSHA256);
  std::thread six(testMD5);
  std::thread seven(testSHA256);
  std::thread eight(testMD5);

  first.join();
  second.join();
  three.join();
  four.join();
  five.join();
  six.join();
  seven.join();
  eight.join();


  std::cout << "--------------------" << std::endl;
}

vector<std::thread> threads;
for (int i = 0; i < 400; i++) {
  threads.push_back(std::thread(testSHA256));
  threads.push_back(std::thread(testMD5));
}

for (auto &t : threads) {
  t.join();
}
  return 0;
}

void testMD5() {
  unsigned char digest[CEPH_CRYPTO_MD5_DIGESTSIZE];

  //MD5 md5(cyInstHandle);
  MD5 md5;

#define BUFFER_SIZE 131072 //(65536 * 2)
  FILE *srcFile = NULL;
  //srcFile = fopen("digest", "r");
  srcFile = fopen("4M", "r");
  //srcFile = fopen("38688", "r");
  if (srcFile == nullptr) {
    std::cout << "failed to open file" << std::endl;
  }
  unsigned char data[BUFFER_SIZE];
  size_t len;

  while (!feof(srcFile)) {
    len = fread(data, 1, BUFFER_SIZE, srcFile);
    //len = fread(data, 1, 38688 + 65536, srcFile);
    //std::cout << "len: " << len << std::endl;
    md5.Update(data, len);
  }
  md5.Final(digest);
  if (memcmp(md5result4M, digest, sizeof(md5result4M)) == 0) {
    // do nothing
  } else {
    for(int i = 0; i < CEPH_CRYPTO_MD5_DIGESTSIZE; i++) {
      printf("%02X", digest[i]);
      printf("%02X", md5result4M[i]);
    }
    printf("\n");
  }
  fclose(srcFile);
}



void testSHA256() {
  unsigned char digest[CEPH_CRYPTO_SHA256_DIGESTSIZE];

  //SHA256 sha256(cyInstHandle);
  SHA256 sha256;

#define BUFFER_SIZE 131072 //(65536 * 2)
  FILE *srcFile = NULL;
  //srcFile = fopen("digest", "r");
  srcFile = fopen("4M", "r");
  //srcFile = fopen("38688", "r");
  if (srcFile == nullptr) {
    std::cout << "failed to open file" << std::endl;
  }
  unsigned char data[BUFFER_SIZE];
  size_t len;

  while (!feof(srcFile)) {
    len = fread(data, 1, BUFFER_SIZE, srcFile);
    //len = fread(data, 1, 38688 + 65536, srcFile);
    //std::cout << "len: " << len << std::endl;
    sha256.Update(data, len);
  }
  sha256.Final(digest);

  if (memcmp(sha256result4M, digest, sizeof(sha256result4M)) == 0) {
  } else {
    for(int i = 0; i < CEPH_CRYPTO_SHA256_DIGESTSIZE; i++) {
      printf("%02X", digest[i]);
    }
    printf("\n");
  }
  fclose(srcFile);
}
