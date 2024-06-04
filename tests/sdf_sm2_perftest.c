#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/hex.h>
#include <gmssl/sm2.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include <gmssl/speed.h>
#include "../src/sdf/sdf.h"
#include "../src/sdf/sdf_ext.h"

#define TEST_KEK_INDEX		1
#define TEST_SM2_KEY_INDEX	1
#define TEST_SM2_KEY_PASS	"123456"


size_t test_SDF_InternalEncrypt_ECC(size_t size)  //内部加密
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiIPKIndex = TEST_SM2_KEY_INDEX;
	unsigned char *ucPassword = (unsigned char *)TEST_SM2_KEY_PASS;
	unsigned int uiPwdLength = (unsigned int)strlen((char *)ucPassword);
	unsigned char ucData[48] = { 1,2,3,4 };
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	ECCCipher eccCipher;
	unsigned char ucDecData[256];
	unsigned int uiDecDataLength;
	int ret;
    size_t count=0;
	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession returned 0x%X\n", ret);
		return -1;
	}

    for (count = 0; run && count < 0xffffffffffffffff; count++)
    {
	// encrypt
	    ret = SDF_InternalEncrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, ucData, uiDataLength, &eccCipher);
    }

	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_InternalEncrypt_ECC return 0x%X\n", ret);
		return -1;
	}
	
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return count;
}

size_t test_SDF_InternalDecrypt_ECC(size_t size)  //内部加密
{

    size_t count=0;
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiIPKIndex = TEST_SM2_KEY_INDEX;
	unsigned char *ucPassword = (unsigned char *)TEST_SM2_KEY_PASS;
	unsigned int uiPwdLength = (unsigned int)strlen((char *)ucPassword);
	unsigned char ucData[48] = { 1,2,3,4 };
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	ECCCipher eccCipher;
	unsigned char ucDecData[256];
	unsigned int uiDecDataLength;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}

    double d=0.0;
    signal(SIGALRM, alarmed); 
    
	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession returned 0x%X\n", ret);
		return -1;
	}

	// encrypt
    
	ret = SDF_InternalEncrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, ucData, uiDataLength, &eccCipher);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_InternalEncrypt_ECC return 0x%X\n", ret);
		return -1;
	}
    


	// decrypt
	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, ucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GetPrivateKeyAccessRight failed with error: 0x%X\n", ret);
		return -1;
	}

    for (count = 0; run && count < 0xffffffffffffffff; count++)
    {
	    ret = SDF_InternalDecrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, &eccCipher, ucDecData, &uiDecDataLength);
    }

	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_InternalDecrypt_ECC return 0x%X\n", ret);
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return count;
}


size_t test_SDF_InternalSign_ECC(size_t size)
{
    size_t count=0;
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiIPKIndex = TEST_SM2_KEY_INDEX;
	unsigned char *ucPassword = (unsigned char *)TEST_SM2_KEY_PASS;
	unsigned int uiPwdLength = (unsigned int)strlen((char *)ucPassword);
	unsigned char ucData[32] = { 1,2,3,4 };
	unsigned int uiDataLength = 32;
	ECCSignature eccSignature;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// sign
    
	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, ucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}
    
	for (count = 0; run && count < 0xffffffffffffffff; count++)
    {
		ret = SDF_InternalSign_ECC(hSessionHandle, uiIPKIndex, ucData, uiDataLength, &eccSignature);
		
	}

	if (ret != SDR_OK) {
			error_print_msg("SDF library: 0x%08X\n", ret);
			return -1;
	}
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return count;

}

size_t test_SDF_InternalVerify_ECC(size_t size)
{
    size_t count=0;
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiIPKIndex = TEST_SM2_KEY_INDEX;
	unsigned char *ucPassword = (unsigned char *)TEST_SM2_KEY_PASS;
	unsigned int uiPwdLength = (unsigned int)strlen((char *)ucPassword);
	unsigned char ucData[32] = { 1,2,3,4 };
	unsigned int uiDataLength = 32;
	ECCSignature eccSignature;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// sign
    
	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, ucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}
    
    
	ret = SDF_InternalSign_ECC(hSessionHandle, uiIPKIndex, ucData, uiDataLength, &eccSignature);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}
    

	ret = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, uiIPKIndex);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// verify
	for (count = 0; run && count < 0xffffffffffffffff; count++)
    {
		ret = SDF_InternalVerify_ECC(hSessionHandle, uiIPKIndex, ucData, uiDataLength, &eccSignature);
		
	}
	
	if (ret != SDR_OK) {
			error_print_msg("SDF library: 0x%08X\n", ret);
			return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return count;

}

int main(void )
{   

	
    if (SDF_LoadLibrary("/home/hjc/GmSSL/build/bin/libsoft_sdf.so", NULL) != SDR_OK) {
		error_print();
		goto err;
	}
    size_t size=48;
	printf("SDF_InternalDecrypt_ECC_Enc_and_Dec:\n");
	performance_test_sv(test_SDF_InternalDecrypt_ECC,test_SDF_InternalDecrypt_ECC,&size,1,10);
	printf("\n\nSDF_InternalDecrypt_ECC_Sign_and_Verify:\n");
    performance_test_sv(test_SDF_InternalSign_ECC,test_SDF_InternalVerify_ECC,&size,1,10);

	
	return 0;
err:
	error_print();
	return 1;
}
