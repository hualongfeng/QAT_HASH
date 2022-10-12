#include <iostream>
#include "crypto.h"
#include <pthread.h>
#include <thread>

using namespace std;


#define MAX_INSTANCES 200

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

//static pthread_t gPollingThread;
static std::thread gPollingThread;
static volatile int gPollingCy = 0;

static void sal_polling(CpaInstanceHandle cyInstHandle)
{
  gPollingCy = 1;
  while (gPollingCy)
  {
    icp_sal_CyPollInstance(cyInstHandle, 0);
    OS_SLEEP(1);
  }
}


void sampleCyStartPolling(CpaInstanceHandle cyInstHandle)
{
  CpaInstanceInfo2 info2;
  CpaStatus status = CPA_STATUS_SUCCESS;

  status = cpaCyInstanceGetInfo2(cyInstHandle, &info2);
  if ((status == CPA_STATUS_SUCCESS) && (info2.isPolled == CPA_TRUE))
  {
    /* Start thread to poll instance */
    gPollingThread = std::thread(sal_polling, cyInstHandle);
  }
}

void sampleCyStopPolling(void)
{
  gPollingCy = 0;
  gPollingThread.join();
}


int main() {
  std::cout << "This is main!!!" << std::endl;
  CpaStatus stat = CPA_STATUS_SUCCESS;


  stat = qaeMemInit();
  if (CPA_STATUS_SUCCESS != stat)
  {
     std::cout << "Failed to initialize memory driver" << std::endl;
     return 0;
  }

  stat = icp_sal_userStartMultiProcess("SHIM", CPA_FALSE);
  if (CPA_STATUS_SUCCESS != stat)
  {
    std::cout << "Failed to start user process SSL" << std::endl;
    qaeMemDestroy();
    return 0;
  }

  CpaInstanceHandle cyInstHandle = NULL;

  CpaInstanceHandle cyInstHandles[MAX_INSTANCES];
  Cpa16U numInstances = 0;
  CpaStatus status = CPA_STATUS_SUCCESS;

  status = cpaCyGetNumInstances(&numInstances);
  if ((status == CPA_STATUS_SUCCESS) && (numInstances > 0))
  {
    status = cpaCyGetInstances(numInstances, cyInstHandles);
    if (status == CPA_STATUS_SUCCESS)
      cyInstHandle = cyInstHandles[0];
  }

  if (0 == numInstances)
  {
    std::cout << "No instances found for 'SSL'" << std::endl;
    std::cout << "Please check your section names" << std::endl;
    std::cout << " in the config file." << std::endl;
    std::cout << "Also make sure to use config file version 2." << std::endl;
  }

  if (cyInstHandle == NULL)
  {
    return CPA_STATUS_FAIL;
  }

  /* Start Cryptographic component */
  std::cout << "cpaCyStartInstance" << std::endl;
  status = cpaCyStartInstance(cyInstHandle);

  if (CPA_STATUS_SUCCESS == status)
  {
    /*
     *  Set the address translation function for the instance
     */
    status = cpaCySetAddressTranslation(cyInstHandle, qaeVirtToPhysNUMA);
  }

  sampleCyStartPolling(cyInstHandle);
//----------------------------------------
  {
  unsigned char digest[CEPH_CRYPTO_MD5_DIGESTSIZE];

  SHA256 sha256(cyInstHandle);

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

  std::cout << "-----------------------------" << std::endl;
  while (!feof(srcFile)) {
    len = fread(data, 1, BUFFER_SIZE, srcFile);
    //len = fread(data, 1, 38688 + 65536, srcFile);
    //std::cout << "len: " << len << std::endl;
    sha256.Update(data, len);
  }
  sha256.Final(digest);
  for(int i = 0; i < CEPH_CRYPTO_SHA256_DIGESTSIZE; i++) {
    printf("%02X", digest[i]);
  }
  std::cout << "\n-----------------------------" << std::endl;
  fclose(srcFile);





  }
//----------------------------------------
  sampleCyStopPolling();
  cpaCyStopInstance(cyInstHandle);
  icp_sal_userStop();
  qaeMemDestroy();


  return 0;
}
