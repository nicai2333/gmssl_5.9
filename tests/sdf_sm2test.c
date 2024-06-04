#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmssl/hex.h>
#include <gmssl/sm2.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include "../src/sdf/sdf.h"
#include "../src/sdf/sdf_ext.h"

#define TEST_KEK_INDEX		1
#define TEST_SM2_KEY_INDEX	1
#define TEST_SM2_KEY_PASS	"123456"


static int generate_kek(unsigned int uiKEKIndex)
{
	char filename[256];
	uint8_t kek[16];
	FILE *file;

	if (rand_bytes(kek, sizeof(kek)) != 1) {
		error_print();
		return -1;
	}

	snprintf(filename, sizeof(filename), "kek-%u.key", uiKEKIndex);
	if (!(file = fopen(filename, "wb"))) {
		error_print();
		return -1;
	}
	if (fwrite(kek, 1, sizeof(kek), file) != sizeof(kek)) {
		fclose(file);
		error_print();
		return -1;
	}
	fclose(file);

	return 1;
}

static int generate_sign_key(unsigned int uiKeyIndex, const char *pass)
{
	SM2_KEY sm2_key;
	SM2_POINT point;

	uint8_t data[32];
	SM2_SIGNATURE sig;
	char filename[256];
	FILE *file;
	int i;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}

	sm2_key_print(stderr, 0, 0, "SDF SignKey", &sm2_key);

	snprintf(filename, sizeof(filename), "sm2sign-%u.pem", uiKeyIndex);
	if ((file = fopen(filename, "wb")) == NULL) {
		fclose(file);
		error_print();
		return -1;
	}
	if (sm2_private_key_info_encrypt_to_pem(&sm2_key, pass, file) != 1) {
		error_print();
		return -1;
	}
	fclose(file);

	snprintf(filename, sizeof(filename), "sm2signpub-%u.pem", uiKeyIndex);
	if ((file = fopen(filename, "wb")) == NULL) {
		fclose(file);
		error_print();
		return -1;
	}
	if (sm2_public_key_info_to_pem(&sm2_key, file) != 1) {
		error_print();
		return -1;
	}
	fclose(file);


	// print public key as ECCrefPublicKey
	sm2_z256_point_to_bytes(&sm2_key.public_key, (uint8_t *)&point);

	printf("ECCrefPublicKey eccPublicKey = {\n");
	printf("256,\n");

	printf("{\n");
	for (i = 0; i < 32; i++) {
		printf("0x00,");
		printf("%s", (i + 1) % 8 ? " " : "\n");
	}
	for (i = 0; i < 32; i++) {
		printf("0x%02x,", point.x[i]);
		printf("%s", (i + 1) % 8 ? " " : "\n");
	}
	printf("},\n");

	printf("{\n");
	for (i = 0; i < 32; i++) {
		printf("0x00,");
		printf("%s", (i + 1) % 8 ? " " : "\n");
	}
	for (i = 0; i < 32; i++) {
		printf("0x%02x,", point.y[i]);
		printf("%s", (i + 1) % 8 ? " " : "\n");
	}
	printf("},\n");

	printf("};\n");



	// print to be signed data
	rand_bytes(data, sizeof(data));
	printf("unsigned char ucData[] = {\n");
	for (i = 0; i < sizeof(data); i++) {
		printf("0x%02x,", data[i]);
		printf("%s", (i + 1) % 8 ? " " : "\n");
	}
	printf("};\n");

	sm2_do_sign(&sm2_key, data, &sig);

	// print ECCSignature

	printf("ECCSignature eccSignature = {\n");

	printf("{\n");
	for (i = 0; i < 32; i++) {
		printf("0x00,");
		printf("%s", (i + 1) % 8 ? " " : "\n");
	}
	for (i = 0; i < 32; i++) {
		printf("0x%02x,", sig.r[i]);
		printf("%s", (i + 1) % 8 ? " " : "\n");
	}
	printf("},\n");

	printf("{\n");
	for (i = 0; i < 32; i++) {
		printf("0x00,");
		printf("%s", (i + 1) % 8 ? " " : "\n");
	}
	for (i = 0; i < 32; i++) {
		printf("0x%02x,", sig.s[i]);
		printf("%s", (i + 1) % 8 ? " " : "\n");
	}
	printf("},\n");

	printf("};\n");


	return 1;
}

static int generate_enc_key(unsigned int uiKeyIndex, const char *pass)
{
	SM2_KEY sm2_key;
	char filename[256];
	FILE *file;
	size_t i;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}

	snprintf(filename, sizeof(filename), "sm2enc-%u.pem", uiKeyIndex);
	if ((file = fopen(filename, "wb")) == NULL) {
		fclose(file);
		error_print();
		return -1;
	}
	if (sm2_private_key_info_encrypt_to_pem(&sm2_key, pass, file) != 1) {
		error_print();
		return -1;
	}
	fclose(file);

	snprintf(filename, sizeof(filename), "sm2encpub-%u.pem", uiKeyIndex);
	if ((file = fopen(filename, "wb")) == NULL) {
		fclose(file);
		error_print();
		return -1;
	}
	if (sm2_public_key_info_to_pem(&sm2_key, file) != 1) {
		error_print();
		return -1;
	}
	fclose(file);

	SM2_POINT point;

	// print public key as ECCrefPublicKey
	sm2_z256_point_to_bytes(&sm2_key.public_key, (uint8_t *)&point);

	printf("ECCrefPublicKey eccPublicKey = {\n");
	printf("256,\n");

	printf("{\n");
	for (i = 0; i < 32; i++) {
		printf("0x00,");
		printf("%s", (i + 1) % 8 ? " " : "\n");
	}
	for (i = 0; i < 32; i++) {
		printf("0x%02x,", point.x[i]);
		printf("%s", (i + 1) % 8 ? " " : "\n");
	}
	printf("},\n");

	printf("{\n");
	for (i = 0; i < 32; i++) {
		printf("0x00,");
		printf("%s", (i + 1) % 8 ? " " : "\n");
	}
	for (i = 0; i < 32; i++) {
		printf("0x%02x,", point.y[i]);
		printf("%s", (i + 1) % 8 ? " " : "\n");
	}
	printf("},\n");

	printf("};\n");


	// 准备待加密的数据
	uint8_t data[48];

	rand_bytes(data, sizeof(data));

	printf("unsigned char ucData[] = {\n");
	for (i = 0; i < sizeof(data); i++) {
		printf("0x%02x,", data[i]);
		printf("%s", (i + 1) % 8 ? " " : "\n");
	}
	printf("};\n");


	// 现在要加密了
	SM2_CIPHERTEXT ciphertext;

	sm2_do_encrypt(&sm2_key, data, sizeof(data), &ciphertext);


	// 打印CIPHERTEXT

	printf("ECCCipher eccCipher = {\n");

		printf("{\n");
		for (i = 0; i < ECCref_MAX_LEN - 32; i++) {
			printf("0x00,");
			printf("%s", (i + 1) % 8 ? " " : "\n");
		}
		for (i = 0; i < 32; i++) {
			printf("0x%02x,", ciphertext.point.x[i]);
			printf("%s", (i + 1) % 8 ? " " : "\n");
		}
		printf("},\n");

		printf("{\n");
		for (i = 0; i < ECCref_MAX_LEN - 32; i++) {
			printf("0x00,");
			printf("%s", (i + 1) % 8 ? " " : "\n");
		}
		for (i = 0; i < 32; i++) {
			printf("0x%02x,", ciphertext.point.y[i]);
			printf("%s", (i + 1) % 8 ? " " : "\n");
		}
		printf("},\n");

		printf("{\n");
		for (i = 0; i < 32; i++) {
			printf("0x%02x,", ciphertext.hash[i]);
			printf("%s", (i + 1) % 8 ? " " : "\n");
		}
		printf("},\n");

		printf("%u,\n", ciphertext.ciphertext_size);

		printf("{\n");
		for (i = 0; i < ciphertext.ciphertext_size; i++) {
			printf("0x%02x,", ciphertext.ciphertext[i]);
			printf("%s", (i + 1) % 8 ? " " : "\n");
		}
		printf("},\n");


	printf("};\n");


	return 1;
}


static int test_SDF_GenerateKeyPair_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	ECCrefPublicKey eccPublicKey;
	ECCrefPrivateKey eccPrivateKey;
	int ret;

	SM2_KEY sm2_key;
	SM2_POINT point;
	SM2_Z256_POINT public_key;
	sm2_z256_t private_key;
	uint8_t zeros[ECCref_MAX_LEN] = {0};

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_GenerateKeyPair_ECC(hSessionHandle, SGD_SM2_1, 256, &eccPublicKey, &eccPrivateKey);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GenerateKeyPair_ECC: 0x%X\n", ret);
		return -1;
	}

	// check public key
	if (eccPublicKey.bits != 256) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.x, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	memcpy(point.x, eccPublicKey.x + ECCref_MAX_LEN - 32, 32);
	memcpy(point.y, eccPublicKey.y + ECCref_MAX_LEN - 32, 32);
	if (sm2_z256_point_from_bytes(&public_key, (uint8_t *)&point) != 1) {
		error_print();
		return -1;
	}

	// check private key
	if (eccPrivateKey.bits != 256) {
		error_print();
		return -1;
	}
	if (memcmp(eccPrivateKey.K, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	sm2_z256_from_bytes(private_key, eccPrivateKey.K + ECCref_MAX_LEN - 32);
	if (sm2_key_set_private_key(&sm2_key, private_key) != 1) {
		error_print();
		return -1;
	}

	// check private/public key
	if (sm2_z256_point_equ(&sm2_key.public_key, &public_key) != 1) {
		error_print();
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


// FIXME: check generated public key is not [n-1]G, i.e. -G
int test_SDF_ExportSignPublicKey_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiKeyIndex = TEST_SM2_KEY_INDEX;
	unsigned char *pucPassword = (unsigned char *)TEST_SM2_KEY_PASS;
	ECCrefPublicKey eccPublicKey;
	uint8_t zeros[ECCref_MAX_LEN] = {0};
	SM2_POINT point;
	SM2_Z256_POINT public_key;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "SDF_OpenDevice failed with error: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "SDF_OpenSession failed with error: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_ExportSignPublicKey_ECC(hSessionHandle, uiKeyIndex, &eccPublicKey);
	if (ret != SDR_OK) {
		printf("SDF_ExportSignPublicKey_ECC failed with error: 0x%X\n", ret);
		return -1;
	}

	// check public key
	if (eccPublicKey.bits != 256) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.x, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	memcpy(point.x, eccPublicKey.x + ECCref_MAX_LEN - 32, 32);
	memcpy(point.y, eccPublicKey.y + ECCref_MAX_LEN - 32, 32);
	if (sm2_z256_point_from_bytes(&public_key, (uint8_t *)&point) != 1) {
		error_print();
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_InternalEncrypt_ECC(void)
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

	ret = SDF_InternalDecrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, &eccCipher, ucDecData, &uiDecDataLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_InternalDecrypt_ECC return 0x%X\n", ret);
		return -1;
	}

	ret = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, uiIPKIndex);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_ReleasePrivateKeyAccessRight return 0x%X\n", ret);
		return -1;
	}

	// check
	if (uiDecDataLength != uiDataLength) {
		fprintf(stderr, "Error: invalid uiDecDataLength\n");
		return -1;
	}
	if (memcmp(ucDecData, ucData, uiDataLength) != 0) {
		fprintf(stderr, "Error: invalid ucDecData\n");
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_InternalSign_ECC(void)
{
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
	ret = SDF_InternalVerify_ECC(hSessionHandle, uiIPKIndex, ucData, uiDataLength, &eccSignature);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;

}

int test_SDF_ExportEncPublicKey_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiKeyIndex = TEST_SM2_KEY_INDEX;
	unsigned char *pucPassword = (unsigned char *)TEST_SM2_KEY_PASS;
	ECCrefPublicKey eccPublicKey;
	uint8_t zeros[ECCref_MAX_LEN] = {0};
	SM2_POINT point;
	SM2_Z256_POINT public_key;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "SDF_OpenDevice failed with error: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "SDF_OpenSession failed with error: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_ExportEncPublicKey_ECC(hSessionHandle, uiKeyIndex, &eccPublicKey);
	if (ret != SDR_OK) {
		printf("SDF_ExportEncPublicKey_ECC failed with error: 0x%X\n", ret);
		return -1;
	}

	// check public key
	if (eccPublicKey.bits != 256) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.x, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	memcpy(point.x, eccPublicKey.x + ECCref_MAX_LEN - 32, 32);
	memcpy(point.y, eccPublicKey.y + ECCref_MAX_LEN - 32, 32);
	if (sm2_z256_point_from_bytes(&public_key, (uint8_t *)&point) != 1) {
		error_print();
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_SDF_GenerateKeyWithEPK_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	ECCrefPublicKey eccPublicKey = {
		256,
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x12, 0xbd, 0x37, 0x95, 0x9d, 0xb3, 0x36,
		0x11, 0x33, 0x04, 0x44, 0x02, 0xfa, 0x83, 0xec,
		0x18, 0x47, 0x1b, 0x5b, 0x2c, 0x98, 0xb5, 0x0e,
		0x49, 0xa3, 0x29, 0x43, 0x92, 0xd1, 0xe5, 0x45,
		},
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x31, 0x17, 0xbe, 0x37, 0xef, 0x88, 0x82, 0x2d,
		0xf5, 0x53, 0xc6, 0xe2, 0xf2, 0x67, 0x77, 0x8a,
		0x80, 0xe0, 0xe1, 0xfa, 0x3c, 0x49, 0xd4, 0x8b,
		0xb0, 0xe4, 0xbe, 0xfd, 0x66, 0xbe, 0xcc, 0x4c,
		},
	};
	ECCCipher eccCipher;
	int ret;


	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_GenerateKeyWithEPK_ECC(hSessionHandle, 128, SGD_SM2_3, &eccPublicKey, &eccCipher, &hKeyHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_GenerateKeyWithEPK_ECC returned 0x%X\n", ret);
		return -1;
	}

	if (hKeyHandle == NULL) {
		error_print();
		return -1;
	}

	if (SDF_DestroyKey(hSessionHandle, hKeyHandle) != SDR_OK) {
		error_print();
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_GenerateKeyWithIPK_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned int uiIPKIndex = TEST_SM2_KEY_INDEX;
	unsigned char *pucPassword = (unsigned char *)TEST_SM2_KEY_PASS;
	unsigned int uiPwdLength = (unsigned int)strlen((char *)pucPassword);
	unsigned int uiKeyBits = 128;
	ECCCipher eccCipher;
	unsigned char ucIV[16];
	unsigned char ucData[32];
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	unsigned char ucEncData[64];
	unsigned int uiEncDataLength;
	unsigned char ucDecData[64];
	unsigned int uiDecDataLength;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession returned 0x%X\n", ret);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	// generate symmetric key and encrypt
	ret = SDF_GenerateKeyWithIPK_ECC(hSessionHandle, uiIPKIndex, uiKeyBits, &eccCipher, &hKeyHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GenerateKeyWithIPK_ECC return 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, ucIV, ucData, uiDataLength, ucEncData, &uiEncDataLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_Encrypt return 0x%X\n", ret);
		SDF_DestroyKey(hSessionHandle, hKeyHandle);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_DestroyKey(hSessionHandle, hKeyHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_DestroyKey return 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}
	hKeyHandle = NULL;

	// import symmetric key and decrypt
	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, pucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GetPrivateKeyAccessRight return 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_ImportKeyWithISK_ECC(hSessionHandle, uiIPKIndex, &eccCipher, &hKeyHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_ImportKeyWithISK_ECC return 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, ucIV, ucEncData, uiEncDataLength, ucDecData, &uiDecDataLength);
	if (ret != SDR_OK) {
		printf("Error: SDF_Encrypt returned 0x%X\n", ret);
		SDF_DestroyKey(hSessionHandle, hKeyHandle);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	if (uiDecDataLength != uiDataLength) {
		fprintf(stderr, "Error: uiDecDataLength != uiDataLength\n");
		SDF_DestroyKey(hSessionHandle, hKeyHandle);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}
	if (memcmp(ucDecData, ucData, uiDataLength) != 0) {
		fprintf(stderr, "Error: ucDecData != ucData\n");
		SDF_DestroyKey(hSessionHandle, hKeyHandle);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	SDF_DestroyKey(hSessionHandle, hKeyHandle);
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

    printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_ExternalVerify_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	ECCrefPublicKey eccPublicKey = {
		256,
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x12, 0xbd, 0x37, 0x95, 0x9d, 0xb3, 0x36,
		0x11, 0x33, 0x04, 0x44, 0x02, 0xfa, 0x83, 0xec,
		0x18, 0x47, 0x1b, 0x5b, 0x2c, 0x98, 0xb5, 0x0e,
		0x49, 0xa3, 0x29, 0x43, 0x92, 0xd1, 0xe5, 0x45,
		},
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x31, 0x17, 0xbe, 0x37, 0xef, 0x88, 0x82, 0x2d,
		0xf5, 0x53, 0xc6, 0xe2, 0xf2, 0x67, 0x77, 0x8a,
		0x80, 0xe0, 0xe1, 0xfa, 0x3c, 0x49, 0xd4, 0x8b,
		0xb0, 0xe4, 0xbe, 0xfd, 0x66, 0xbe, 0xcc, 0x4c,
		},
	};
	unsigned char ucData[] = {
		0xac, 0xba, 0xa9, 0x0f, 0xab, 0x42, 0x9f, 0x58,
		0x72, 0x05, 0xeb, 0x4a, 0xb3, 0xa2, 0x16, 0x70,
		0x1a, 0x0d, 0xef, 0xfe, 0x10, 0xea, 0x76, 0x8f,
		0x7d, 0x89, 0x33, 0x7a, 0xcc, 0xbe, 0x9b, 0x9e,
	};
	ECCSignature eccSignature = {
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x50, 0x52, 0x4e, 0xee, 0xa7, 0x6c, 0x91, 0x4e,
		0xd5, 0x75, 0xab, 0xa1, 0x74, 0xcf, 0x34, 0x18,
		0xae, 0xb0, 0x5e, 0x34, 0x29, 0xd5, 0xff, 0x90,
		0x09, 0x93, 0xaf, 0x6b, 0x4d, 0x1c, 0xf5, 0x4f,
		},
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x76, 0xf0, 0xba, 0xd1, 0x97, 0x4d, 0x2b, 0xa8,
		0x08, 0x9e, 0xc4, 0x7b, 0x75, 0x06, 0x05, 0x89,
		0x8f, 0xab, 0x60, 0xce, 0xc7, 0x27, 0x98, 0x41,
		0x3e, 0xb4, 0xb6, 0x66, 0x20, 0x52, 0x0c, 0xf4,
		},
	};
	unsigned char saved_byte;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice return 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession returned 0x%X\n", ret);
		return -1;
	}

	// verify correct signature
	ret = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, &eccPublicKey, ucData, (unsigned int)sizeof(ucData), &eccSignature);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_ExternalVerify_ECC returned 0x%X\n", ret);
		return -1;
	}

    SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_ExternalEncrypt_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	ECCrefPublicKey eccPublicKey;
	unsigned char ucData[48];
	ECCCipher eccCipher;
	int ret;

	SM2_KEY sm2_key;
	SM2_POINT point;
	SM2_CIPHERTEXT ciphertext;
	const uint8_t zeros[ECCref_MAX_LEN] = {0};
	uint8_t plaintext[SM2_MAX_PLAINTEXT_SIZE];
	size_t plaintext_len;
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

	// generate SM2_KEY and convert public key to ECCrefPublicKey
	// Note: when testing SDF_ExternalEncrypt_ECC, we should not assume IPK exists
	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}
	if (sm2_z256_point_to_bytes(&sm2_key.public_key, (uint8_t *)&point) != 1) {
		error_print();
		return -1;
	}
	eccPublicKey.bits = 256;
	memset(eccPublicKey.x, 0, ECCref_MAX_LEN - 32);
	memcpy(eccPublicKey.x + ECCref_MAX_LEN - 32, point.x, 32);
	memset(eccPublicKey.y, 0, ECCref_MAX_LEN - 32);
	memcpy(eccPublicKey.y + ECCref_MAX_LEN - 32, point.y, 32);

	// encrypt
	if (rand_bytes(ucData, sizeof(ucData)) != 1) {
		error_print();
		return -1;
	}
	ret = SDF_ExternalEncrypt_ECC(hSessionHandle, SGD_SM2_3, &eccPublicKey, ucData, (unsigned int)sizeof(ucData), &eccCipher);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	// convert ECCCipher to SM2_CIPHERTEXT
	if (memcmp(eccCipher.x, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(eccCipher.y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	if (eccCipher.L > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}
	memcpy(ciphertext.point.x, eccCipher.x + ECCref_MAX_LEN - 32, 32);
	memcpy(ciphertext.point.y, eccCipher.y + ECCref_MAX_LEN - 32, 32);
	memcpy(ciphertext.hash, eccCipher.M, 32);
	ciphertext.ciphertext_size = eccCipher.L;
	memcpy(ciphertext.ciphertext, eccCipher.C, eccCipher.L);

	// decrypt and check plaintext
	if (sm2_do_decrypt(&sm2_key, &ciphertext, plaintext, &plaintext_len) != 1) {
		error_print();
		return -1;
	}

	if (plaintext_len != sizeof(ucData)) {
		error_print();
		return -1;
	}
	if (memcmp(plaintext, ucData, sizeof(ucData)) != 0) {
		error_print();
		return -1;
	}


	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void )
{   

    if (generate_kek(TEST_KEK_INDEX) != 1) {
		error_print();
		goto err;
	}
	if (generate_sign_key(TEST_SM2_KEY_INDEX, TEST_SM2_KEY_PASS) != 1) {
		error_print();
		goto err;
	}
	if (generate_enc_key(TEST_SM2_KEY_INDEX, TEST_SM2_KEY_PASS) != 1) {
		error_print();
		goto err;
	}
	
    if (SDF_LoadLibrary("/home/hjc/GmSSL/build/bin/libsoft_sdf.so", NULL) != SDR_OK) {
		error_print();
		goto err;
	}
    
    if (test_SDF_GenerateKeyPair_ECC() != 1) goto err;
	if (test_SDF_ExportSignPublicKey_ECC() != 1) goto err;
	if (test_SDF_ExportEncPublicKey_ECC() != 1) goto err;
	if (test_SDF_GenerateKeyWithEPK_ECC() != 1) goto err;
	if (test_SDF_GenerateKeyWithIPK_ECC() != 1) goto err;
	if (test_SDF_ExternalVerify_ECC() != 1) goto err;
	if (test_SDF_ExternalEncrypt_ECC() != 1) goto err; //FIXME: test this before any ECCCipher used
	if (test_SDF_InternalSign_ECC() != 1) goto err;
	if (test_SDF_InternalEncrypt_ECC() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
