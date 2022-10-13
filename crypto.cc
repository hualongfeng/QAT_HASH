#include "crypto.h"
#include <iostream>
#include <semaphore.h>
#include <string.h>
#include <vector>
#include <atomic>
#include <mutex>
#include <thread>

extern "C" {
#include "cpa.h"
#include "lac/cpa_cy_sym.h"
#include "lac/cpa_cy_im.h"
#include "qae_mem.h"
#include "icp_sal_user.h"
#include "icp_sal_poll.h"
#include "qae_mem_utils.h"
}

#define BUFFER_SIZE 131072 //(65536 * 2)
//#define BUFFER_SIZE 65536

struct completion_struct
{
  sem_t semaphore;
};
/* Use semaphores to signal completion of events */
#define COMPLETION_STRUCT completion_struct

#define COMPLETION_INIT(s) sem_init(&((s)->semaphore), 0, 0);

#define COMPLETION_WAIT(s, timeout) (sem_wait(&((s)->semaphore)) == 0)

#define COMPLETE(s) sem_post(&((s)->semaphore))

#define COMPLETION_DESTROY(s) sem_destroy(&((s)->semaphore))

static __inline CpaStatus msSleep(Cpa32U ms)
{
  int ret = 0;
  struct timespec resTime, remTime;
  resTime.tv_sec = ms / 1000;
  resTime.tv_nsec = (ms % 1000) * 1000000;
  do {
    ret = nanosleep(&resTime, &remTime);
    resTime = remTime;
  } while ((ret != 0) && (errno == EINTR));

  if (ret != 0) {
    std::cout << "nanoSleep failed with code "<< ret << std::endl;
    return CPA_STATUS_FAIL;
  } else {
    return CPA_STATUS_SUCCESS;
  }
}

class QatInstancesManager {
  std::vector<CpaInstanceHandle> cyInstances;
  std::mutex lock;
  std::atomic<size_t> index{0};
  std::thread poll_thread;
  volatile bool gPollingCy{false};
 public:
  void poll_instance();
  QatInstancesManager();
  ~QatInstancesManager();
  CpaInstanceHandle getInstance();
};

QatInstancesManager::QatInstancesManager() : index(0) {
  CpaStatus stat = CPA_STATUS_SUCCESS;
  Cpa16U numInstances = 0;
  std::cout << "QatInstancesManager constructor" << std::endl;

  stat = qaeMemInit();
  if (CPA_STATUS_SUCCESS != stat)
  {
    std::cout << "Failed to initialize memory driver" << std::endl;
    throw "Failed to initialize memory driver";
  }

  stat = icp_sal_userStartMultiProcess("SHIM", CPA_FALSE);
  if (CPA_STATUS_SUCCESS != stat)
  {
    std::cout << "Failed to start user process SHIM" << std::endl;
    qaeMemDestroy();
    throw "Failed to start user process SHIM";
  }

  stat = cpaCyGetNumInstances(&numInstances);
  if ((stat == CPA_STATUS_SUCCESS) && (numInstances > 0)) {
    cyInstances.resize(numInstances);
    stat = cpaCyGetInstances(numInstances, &cyInstances[0]);
  }

  if ((stat != CPA_STATUS_SUCCESS) || (numInstances == 0)) {
    icp_sal_userStop();
    qaeMemDestroy();

    std::cout << "No instances found for 'SHIM'" << std::endl;
    throw "No instances found for 'SHIM'";
  }

  std::cout << "cpaCyStartInstance: " << numInstances << std::endl;
  for (auto &instance : cyInstances) {
    cpaCyStartInstance(instance);
    cpaCySetAddressTranslation(instance, qaeVirtToPhysNUMA);
    CpaInstanceInfo2 info2;
    stat = cpaCyInstanceGetInfo2(instance, &info2);
    if ((stat == CPA_STATUS_SUCCESS) && (info2.isPolled == CPA_TRUE)) {
      /*do nothing*/
    } else {
      icp_sal_userStop();
      qaeMemDestroy();

      std::cout << "One instance cannot poll, check the config" << std::endl;
      throw "One instance cannot poll, check the config";
    }
  }
  std::cout << "start poll instance" << std::endl;
  poll_thread = std::thread(&QatInstancesManager::poll_instance, this);
}

QatInstancesManager::~QatInstancesManager() {
  std::cout << "QatInstancesManager destructor" << std::endl;
  gPollingCy = false;
  poll_thread.join();
  for (auto &instance : cyInstances) {
    cpaCyStopInstance(instance);
  }
  icp_sal_userStop();
  qaeMemDestroy();
}

CpaInstanceHandle QatInstancesManager::getInstance() {
  std::lock_guard<std::mutex> l{lock};
  CpaInstanceHandle instance = cyInstances[index++];
  if (index > cyInstances.size()) index = 0;
  return instance;
}

void QatInstancesManager::poll_instance() {
  gPollingCy = true;
  while (gPollingCy) {
    Cpa64U requestsCount = 0;
    int cnt = 0;
    for (auto &instance : cyInstances) {
      CpaCySymStats64 stat{0};
      cpaCySymQueryStats64(instance, &stat);
      std::cout << "numSymOpRequests = " << stat.numSymOpRequests
                << ", numSymOpCompleted = " << stat.numSymOpCompleted
                << ", numSessionsInitialized = " << stat.numSessionsInitialized
                << ", numSessionsRemoved = " << stat.numSessionsRemoved
		<< ", num = " << cnt++
                << std::endl;

      requestsCount += (stat.numSymOpRequests - stat.numSymOpCompleted);
      if (stat.numSymOpRequests != stat.numSymOpCompleted) {
        icp_sal_CyPollInstance(instance, 0);
      }
    }
    if (requestsCount == 0) {
      msSleep(1);
    }
  }
}

static inline void qcc_contig_mem_free(void **ptr) {
  if (*ptr) {
    qaeMemFreeNUMA(ptr);
    *ptr = nullptr;
  }
}

static inline CpaStatus qcc_contig_mem_alloc(void **ptr, Cpa32U size, Cpa32U alignment = 1) {
  *ptr = qaeMemAllocNUMA(size, 0, alignment);
  if (nullptr == *ptr) {
    return CPA_STATUS_RESOURCE;
  }
  return CPA_STATUS_SUCCESS;
}

static void symCallback(void *pCallbackTag,
                        CpaStatus status,
                        const CpaCySymOp operationType,
                        void *pOpData,
                        CpaBufferList *pDstBuffer,
                        CpaBoolean verifyResult)
{
  //std::cout << "Callback called with status = " << status << std::endl;

  if (nullptr != pCallbackTag)
  {
    /** indicate that the function has been called*/
    COMPLETE((struct COMPLETION_STRUCT *)pCallbackTag);
  }
}


static Cpa32U digest_size(CpaCySymHashAlgorithm _type) {
  switch(_type) {
    case CPA_CY_SYM_HASH_MD5:
      return CEPH_CRYPTO_MD5_DIGESTSIZE;
    case CPA_CY_SYM_HASH_SHA1:
      return CEPH_CRYPTO_SHA1_DIGESTSIZE;
    case CPA_CY_SYM_HASH_SHA256:
      return CEPH_CRYPTO_SHA256_DIGESTSIZE;
    case CPA_CY_SYM_HASH_SHA512:
      return CEPH_CRYPTO_SHA512_DIGESTSIZE;
  }
  return -1;
}

static Cpa32U block_size(CpaCySymHashAlgorithm _type) {
  switch(_type) {
    case CPA_CY_SYM_HASH_MD5:
      return LAC_HASH_MD5_BLOCK_SIZE;
    case CPA_CY_SYM_HASH_SHA1:
      return LAC_HASH_SHA1_BLOCK_SIZE;
    case CPA_CY_SYM_HASH_SHA256:
      return LAC_HASH_SHA256_BLOCK_SIZE;
    case CPA_CY_SYM_HASH_SHA512:
      return LAC_HASH_SHA512_BLOCK_SIZE;
  }
  return -1;
}

static QatInstancesManager qat_instance_manager;

QatHashCommon::QatHashCommon(const CpaCySymHashAlgorithm _type)
	: cyInstHandle(qat_instance_manager.getInstance()), mpType(_type) {
  CpaStatus status = CPA_STATUS_SUCCESS;
  digest_length = digest_size(mpType);
  block_length = block_size(mpType);
  memset(&sessionSetupData, 0, sizeof(sessionSetupData));
  sessionSetupData.sessionPriority = CPA_CY_PRIORITY_NORMAL;
  sessionSetupData.symOperation = CPA_CY_SYM_OP_HASH;
  sessionSetupData.hashSetupData.hashAlgorithm = mpType;
  sessionSetupData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_PLAIN;
  sessionSetupData.hashSetupData.digestResultLenInBytes = digest_length;
  sessionSetupData.digestIsAppended = CPA_FALSE;
  sessionSetupData.verifyDigest = CPA_FALSE;
}

QatHashCommon::~QatHashCommon() {
  void *pBufferMeta = nullptr;
  void *pSrcBuffer = nullptr;
  void *pDigestBuffer = nullptr;

  if (pBufferList != nullptr) {
    pBufferMeta   = pBufferList->pPrivateMetaData;
    pDigestBuffer = pBufferList->pUserData;
    pSrcBuffer    = pBufferList->pBuffers->pData;
    qcc_contig_mem_free(&pSrcBuffer);
    free(pBufferList);
    qcc_contig_mem_free(&pBufferMeta);
    qcc_contig_mem_free((void**)&pDigestBuffer);
  }
 
  if (sessionCtx != nullptr) {
    CpaBoolean sessionInUse = CPA_FALSE;
    do {
      cpaCySymSessionInUse(sessionCtx, &sessionInUse);
    } while (sessionInUse);

    cpaCySymRemoveSession(cyInstHandle, sessionCtx);
    qcc_contig_mem_free((void**)&sessionCtx);
  }
}

void QatHashCommon::Restart() {
  CpaStatus status = CPA_STATUS_SUCCESS;
  Cpa32U sessionCtxSize;
  if (sessionCtx == nullptr) {
    // first need to alloc session memory
    status = cpaCySymSessionCtxGetSize(cyInstHandle, &sessionSetupData, &sessionCtxSize);
    if (status != CPA_STATUS_SUCCESS) {
      std::cout <<  "cpaCySymSessionCtxGetSize failed, stat = " << status << std::endl;
      throw "cpaCySymSessionCtxGetSize failed";
    }
    status = qcc_contig_mem_alloc((void**)&sessionCtx, sessionCtxSize);
    if (status != CPA_STATUS_SUCCESS) {
      std::cout << "Failed to alloc contiguous memory for SessionCtx, stat = " << status << std::endl;
      throw "Failed to alloc contiguous memory for SessionCtx";
    }
  }

  status = cpaCySymInitSession(cyInstHandle, symCallback, &sessionSetupData, sessionCtx);
  if (status != CPA_STATUS_SUCCESS) {
    std::cout << "cpaCySymInitSession failed, stat = " << status << std::endl;;
    throw "cpaCySymInitSession failed";
  }
}

/*******************************************************************************************
 **   -----------------|---------------------------|
 **                    |-------numBuffers----------|
 **    CpaBufferList   |-------pBuffers------------|-----
 **                    |-------pUserData-----------|    |
 **                    |-------pPrivateMetaData----|    |
 **   -----------------|---------------------------|<----
 **                    |-------dataLenInByte-------|      -----------------------------
 **    CpaFlatBuffer   |-------pData---------------|---->|contiguous memory| pSrcBuffer
 **   -----------------|---------------------------|      -----------------------------
*********************************************************************************************/

CpaBufferList* QatHashCommon::getCpaBufferList() {

  CpaStatus status = CPA_STATUS_SUCCESS;
  Cpa8U *pBufferMeta = nullptr;
  Cpa32U bufferMetaSize = 0;
  CpaBufferList *pBufferList = nullptr;
  CpaFlatBuffer *pFlatBuffer = nullptr;
  Cpa32U bufferSize = BUFFER_SIZE;
  Cpa32U numBuffers = 1;
  Cpa32U bufferListMemSize = sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));
  Cpa8U *pSrcBuffer = nullptr;
  Cpa8U *pDigestBuffer = nullptr;
 
  status = cpaCyBufferListGetMetaSize(cyInstHandle, numBuffers, &bufferMetaSize);

  if (CPA_STATUS_SUCCESS == status)
  {
    status = qcc_contig_mem_alloc((void**)&pBufferMeta, bufferMetaSize);
  }

  if (CPA_STATUS_SUCCESS == status)
  {
    pBufferList = (CpaBufferList *)malloc(bufferListMemSize);
    if (pBufferList == nullptr) return nullptr;
  }

  if (CPA_STATUS_SUCCESS == status)
  {
    status = qcc_contig_mem_alloc((void**)&pSrcBuffer, bufferSize);
  }

  if (CPA_STATUS_SUCCESS == status)
  {
    status = qcc_contig_mem_alloc((void**)&pDigestBuffer, digest_length);
  }

  if (CPA_STATUS_SUCCESS == status)
  {
    /* increment by sizeof(CpaBufferList) to get at the
     * array of flatbuffers */
    pFlatBuffer = (CpaFlatBuffer *)(pBufferList + 1);

    pBufferList->numBuffers = 1;
    pBufferList->pBuffers = pFlatBuffer;
    pBufferList->pUserData = pDigestBuffer;
    pBufferList->pPrivateMetaData = pBufferMeta;

    pFlatBuffer->dataLenInBytes = bufferSize;
    pFlatBuffer->pData = pSrcBuffer;

  }

  return pBufferList;
}

void QatHashCommon::Update(const unsigned char *input, size_t length) {
  CpaStatus status = CPA_STATUS_SUCCESS;
  CpaCySymOpData pOpData = {0};

  size_t left_length = length;
  size_t current_length = 0;
  size_t new_write_length = 0;
  size_t current_align_left_len = 0;

  if (pBufferList == nullptr) {
    pBufferList = getCpaBufferList();

    if (pBufferList == nullptr) {
      std::cout << "cannot get CpaBufferList" << std::endl;
      return;
    }
  }

  struct COMPLETION_STRUCT complete;

  COMPLETION_INIT((&complete));

  do {
    new_write_length = left_length > (BUFFER_SIZE - align_left_len) ? \
	    (BUFFER_SIZE - align_left_len) : left_length;
    current_length = new_write_length + align_left_len;
    left_length -= new_write_length;

    if (current_length % block_length == 0) {
      memcpy(pBufferList->pBuffers->pData, align_left, align_left_len);
      memcpy(pBufferList->pBuffers->pData + align_left_len, input, new_write_length);
      align_left_len = 0;
    } else if (current_length / block_length > 0){
      memcpy(pBufferList->pBuffers->pData, align_left, align_left_len);
      current_align_left_len = current_length % block_length;
      memcpy(pBufferList->pBuffers->pData + align_left_len, input, new_write_length - current_align_left_len);
      memcpy(align_left, input + new_write_length - current_align_left_len, current_align_left_len);
      align_left_len = current_align_left_len;
      current_length -= align_left_len;
    } else {
      memcpy(align_left + align_left_len, input, new_write_length);
      align_left_len += new_write_length;
      break ;
    }

    input += new_write_length;

    pBufferList->pBuffers->dataLenInBytes = current_length;
    pOpData.packetType = CPA_CY_SYM_PACKET_TYPE_PARTIAL;
    pOpData.sessionCtx = sessionCtx;
    pOpData.hashStartSrcOffsetInBytes = 0;
    pOpData.messageLenToHashInBytes = current_length;
    pOpData.pDigestResult = (Cpa8U *)pBufferList->pUserData;
    do {
      status = cpaCySymPerformOp(
        cyInstHandle,
        (void *)&complete,
        &pOpData,
        pBufferList,
        pBufferList,
        NULL);
    } while (status == CPA_STATUS_RETRY);
    if (CPA_STATUS_SUCCESS != status) {
      std::cout << "Update cpaCySymPerformOp failed. (status = " << status << std::endl;
    }
   
    if (CPA_STATUS_SUCCESS == status) {
      if (!COMPLETION_WAIT((&complete), TIMEOUT_MS)) {
        std::cout << "timeout or interruption in cpaCySymPerformOp" << std::endl;
      }
    }
  } while (left_length > 0);
  COMPLETION_DESTROY(&complete);
}

void QatHashCommon::Final(unsigned char *digest) {
  CpaStatus status = CPA_STATUS_SUCCESS;
  if (pBufferList == nullptr) return;
  CpaCySymOpData pOpData = {0};

  struct COMPLETION_STRUCT complete;

  COMPLETION_INIT((&complete));

  pBufferList->pBuffers->dataLenInBytes = 0;
  if (block_length > 0) {
    memcpy(pBufferList->pBuffers->pData, align_left, align_left_len);
    pBufferList->pBuffers->dataLenInBytes = align_left_len;
  }

  pOpData.packetType = CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL;
  pOpData.sessionCtx = sessionCtx;
  pOpData.hashStartSrcOffsetInBytes = 0;
  pOpData.messageLenToHashInBytes = pBufferList->pBuffers->dataLenInBytes;
  pOpData.pDigestResult = (Cpa8U *)pBufferList->pUserData;

  do {
    status = cpaCySymPerformOp(
      cyInstHandle,
      (void *)&complete,
      &pOpData,
      pBufferList,
      pBufferList,
      NULL);

  } while (status == CPA_STATUS_RETRY);
  if (CPA_STATUS_SUCCESS != status) {
    std::cout << "Final cpaCySymPerformOp failed. (status = " << status << std::endl;
  }
 
  if (CPA_STATUS_SUCCESS == status) {
    if (!COMPLETION_WAIT((&complete), TIMEOUT_MS)) {
      std::cout << "timeout or interruption in cpaCySymPerformOp" << std::endl;
    }
  }
  COMPLETION_DESTROY(&complete);

  memcpy(digest, pOpData.pDigestResult, digest_length);
}
