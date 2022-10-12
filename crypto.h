#ifndef CRYPTO_H
#define CRYPTO_H

extern "C" {
#include "cpa.h"
#include "lac/cpa_cy_sym.h"
#include "lac/cpa_cy_im.h"
#include "qae_mem.h"
#include "icp_sal_user.h"
#include "icp_sal_poll.h"
#include "qae_mem_utils.h"
}


#define CEPH_CRYPTO_MD5_DIGESTSIZE    16
#define CEPH_CRYPTO_SHA1_DIGESTSIZE   20
#define CEPH_CRYPTO_SHA256_DIGESTSIZE 32
#define CEPH_CRYPTO_SHA512_DIGESTSIZE 64

#define CEPH_CRYPTO_HMACSHA1_DIGESTSIZE   20
#define CEPH_CRYPTO_HMACSHA256_DIGESTSIZE 32

//quickassist/lookaside/access_layer/src/common/crypto/sym/include/lac_sym_hash_defs.h
#define LAC_HASH_MD5_BLOCK_SIZE    64
#define LAC_HASH_SHA1_BLOCK_SIZE   64
#define LAC_HASH_SHA256_BLOCK_SIZE 64
#define LAC_HASH_SHA512_BLOCK_SIZE 128
#define LAC_HASH_MAX_BLOCK_SIZE LAC_HASH_SHA512_BLOCK_SIZE

/*
typedef enum _CpaCySymHashAlgorithm
{
  CPA_CY_SYM_HASH_NONE = 0,
  CPA_CY_SYM_HASH_MD5,
  CPA_CY_SYM_HASH_SHA1,
  CPA_CY_SYM_HASH_SHA224,
  CPA_CY_SYM_HASH_SHA256,
  CPA_CY_SYM_HASH_SHA384,
  CPA_CY_SYM_HASH_SHA512,
} CpaCySymHashAlgorithm;
*/


class QatHashCommon {
 private:
  CpaInstanceHandle cyInstHandle{nullptr};
  CpaCySymHashAlgorithm mpType{CPA_CY_SYM_HASH_NONE};
  CpaCySymSessionCtx sessionCtx{nullptr};
  CpaBufferList *pBufferList{nullptr};
  size_t digest_length{0};
  CpaBufferList* getCpaBufferList();
  // partial packet need to align block length
  size_t block_length{0};
  unsigned char align_left[LAC_HASH_MAX_BLOCK_SIZE];
  size_t align_left_len{0};
 protected:
  CpaCySymSessionSetupData sessionSetupData;
 public:
  QatHashCommon (const CpaInstanceHandle cyInstHandle, const CpaCySymHashAlgorithm mpType);
  ~QatHashCommon ();
  void Restart();
  void SetFlags(int flags){}
  void Update(const unsigned char *input, size_t length);
  void Final(unsigned char *digest);
};


class QatDigest : public QatHashCommon {
 public:
  QatDigest (const CpaInstanceHandle cyInstHandle, const CpaCySymHashAlgorithm mpType) :
	  QatHashCommon(cyInstHandle, mpType) {
    this->Restart();
  }
};

class MD5 : public QatDigest {
 public:
  static constexpr size_t digest_size = CEPH_CRYPTO_MD5_DIGESTSIZE;
  MD5(const CpaInstanceHandle cyInstHandle) : QatDigest(cyInstHandle, CPA_CY_SYM_HASH_MD5) {}
};

class SHA1 : public QatDigest {
 public:
  static constexpr size_t digest_size = CEPH_CRYPTO_SHA1_DIGESTSIZE;
  SHA1(const CpaInstanceHandle cyInstHandle) : QatDigest(cyInstHandle, CPA_CY_SYM_HASH_SHA1) {}
};

class SHA256 : public QatDigest {
 public:
  static constexpr size_t digest_size = CEPH_CRYPTO_SHA256_DIGESTSIZE;
  SHA256(const CpaInstanceHandle cyInstHandle) : QatDigest(cyInstHandle, CPA_CY_SYM_HASH_SHA256) {}
};

class SHA512 : public QatDigest {
 public:
  static constexpr size_t digest_size = CEPH_CRYPTO_SHA512_DIGESTSIZE;
  SHA512(const CpaInstanceHandle cyInstHandle) : QatDigest(cyInstHandle, CPA_CY_SYM_HASH_SHA512) {}
};



class QatHMAC : public QatHashCommon {
 public:
  QatHMAC (const CpaInstanceHandle cyInstHandle, const CpaCySymHashAlgorithm mpType,
	   const unsigned char *key, size_t length) :
	  QatHashCommon(cyInstHandle, mpType) {
    sessionSetupData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
    sessionSetupData.hashSetupData.authModeSetupData.authKey = const_cast<Cpa8U*>(key);
    sessionSetupData.hashSetupData.authModeSetupData.authKeyLenInBytes = length;
    this->Restart();
  }
};

class HMACSHA1 : public QatHMAC {
 public:
  static constexpr size_t digest_size = CEPH_CRYPTO_HMACSHA1_DIGESTSIZE;
  HMACSHA1(const CpaInstanceHandle cyInstHandle,
	   const unsigned char *key, size_t length) :
	  QatHMAC(cyInstHandle, CPA_CY_SYM_HASH_SHA1, key, length){}
};

class HMACSHA256 : public QatHMAC {
 public:
  static constexpr size_t digest_size = CEPH_CRYPTO_HMACSHA256_DIGESTSIZE;
  HMACSHA256(const CpaInstanceHandle cyInstHandle,
	   const unsigned char *key, size_t length) :
	  QatHMAC(cyInstHandle, CPA_CY_SYM_HASH_SHA256, key, length){}
};



#endif //CRYPTO_H
