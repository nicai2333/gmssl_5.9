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
#include "test.h"

#define TEST_KEK_INDEX		1
#define TEST_SM2_KEY_INDEX	1
#define TEST_SM2_KEY_PASS	"123456"

#define TEST(function, ...)                                                                        \
    do                                                                                             \
    {                                                                                              \
        int return_value = function(__VA_ARGS__);                                                  \
        if (return_value != SDR_OK)                                                                \
        {                                                                                          \
            printf("Test " #function " failed, return value: 0x%08x.\n", return_value);   \
                                                                                             \
            return -1;                                                                             \
        }                                                                                          \
        else                                                                                       \
        {                                                                                          \
            printf("Test " #function " success.\n");                                               \
        }                                                                                          \
    } while (0)

typedef struct {
    /* input (byte) */
    char *in;
    /* hash (hex) */
    char *hash;
} SM3_TEST_VECTOR;

/* you can add more test vectors here :) */
static SM3_TEST_VECTOR sm3_test_vec[] =
{
    /* 1 */
    {
        "abc",
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
    },
    /* 2 */
    {
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
    },
    /* 3 */
    {
        "123",
        "6e0f9e14344c5406a0cf5a3b4dfb665f87f4a771a31f7edbb5c72874a32b2957",
    },
    /* 4 */
    {
        "123123123123123123123123123123123123123123123123",
        "7eee4a57c9dacce064533d4be457b42b6d60195464f066d2da0e7ccd1dda8814",
    },
    /* 5 */
    {
        "Crazy Thursday",
        "27542186a1f429c4e6ed751712844b433d8b33ad8edd05f7f5f1fb0c682ee51b",
    },
    /* 6 */
    {
        "hello world",
        "44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88",
    },
};

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


static int SM3_Hash(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned char ucHash[32];
	unsigned int uiHashLength;
	int ret;
    printf("test4\n");

	ret = SDF_OpenDevice(&hDeviceHandle);
     printf("test1\n");
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
		return -1;
	}
     printf("test5\n");

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession: 0x%X\n", ret);
		return -1;
	}

	for(int i=0;i<sizeof(sm3_test_vec) / sizeof(SM3_TEST_VECTOR); i++){
    ret = SDF_HashInit(hSessionHandle, SGD_SM3, NULL, NULL, 0);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_HashInit: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_HashUpdate(hSessionHandle, (unsigned char*)sm3_test_vec[i].in, strlen(sm3_test_vec[i].in));
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_HashUpdate: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_HashFinal(hSessionHandle, ucHash, &uiHashLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_HashFinal: 0x%X\n", ret);
		return -1;
	}

	// check correctness
	if (uiHashLength != 32) {
		error_print();
		return -1;
	}
    unsigned char h1[32];
    hex_to_unsigned_char(h1, (unsigned char*)sm3_test_vec[i].hash, 64);
	if (memcmp(ucHash, h1, 32) != 0) {
		error_print();
        printf("sm3 test case %d failed\n", i+1);
            print_hex("hash = ", ucHash, 32);
            printf("hash should be:\n");
            print_hex("hash = ", h1, 32);
		return -1;
	}
    }

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int SM3_Hash_Z(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	ECCrefPublicKey publicKeyRef = {
		256,
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xb6, 0xaf, 0x0c, 0xda, 0xba, 0xdc, 0x18, 0xb4,
		0x65, 0xf5, 0x3f, 0xc3, 0xde, 0x1e, 0x32, 0x87,
		0x89, 0xdc, 0x68, 0xde, 0x92, 0xf1, 0x20, 0xa4,
		0x0a, 0x2e, 0xbb, 0xdb, 0xf1, 0xbd, 0xa8, 0x39,
		},
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 0xff, 0x30, 0x5b, 0x95, 0xf9, 0x94, 0x1a,
		0x92, 0x74, 0x36, 0x42, 0x6f, 0xd2, 0xdf, 0xf2,
		0xfa, 0xf6, 0x08, 0x79, 0x57, 0x7a, 0x95, 0x96,
		0x54, 0xb3, 0xf1, 0x50, 0xba, 0x79, 0xdb, 0x86,
		},
	};
	unsigned char ucID[] = {
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	};
	unsigned int uiIDLength = 16;
	unsigned char ucData[3] = { 0x61, 0x62, 0x63 };
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	unsigned char ucHash[32];
	unsigned int uiHashLength;
	const unsigned char ucHashResult[32] = {
		0x87, 0xb7, 0xd6, 0x24, 0xce, 0x4b, 0xb0, 0x0a,
		0xc5, 0x6d, 0xb2, 0xb6, 0xc5, 0x06, 0xd5, 0xfc,
		0x9e, 0x38, 0xfd, 0x80, 0xc2, 0x4d, 0x1b, 0x99,
		0x1e, 0x8c, 0x38, 0xb3, 0x2b, 0xd6, 0xee, 0x5a,
	};
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

	ret = SDF_HashInit(hSessionHandle, SGD_SM3, &publicKeyRef, ucID, uiIDLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_HashInit: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_HashUpdate(hSessionHandle, ucData, uiDataLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_HashUpdate: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_HashFinal(hSessionHandle, ucHash, &uiHashLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_HashFinal: 0x%X\n", ret);
		return -1;
	}

	// check correctness
	if (uiHashLength != 32) {
		error_print();
		return -1;
	}
	if (memcmp(ucHash, ucHashResult, 32) != 0) {
		error_print();
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int SM3_CalculateMAC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned int uiHMACKeyBits = 256;
	unsigned int uiKeyEncAlgID = SGD_SM4_CBC;
	unsigned int uiKEKIndex = TEST_KEK_INDEX;
	unsigned char ucEncedKey[256];
	unsigned int uiEncedKeyLength = (unsigned int)sizeof(ucEncedKey);
	unsigned int uiMACAlgID = SGD_SM3;
	unsigned char ucData[50] = {0}; // FIXME: 这里给出实际测试数据
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	unsigned char ucMAC[32];
	unsigned int uiMACLength = (unsigned int)sizeof(ucMAC);
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

	// 这个实际上无法测试正确性！因为你都不知道生成的密钥是什么
	ret = SDF_GenerateKeyWithKEK(hSessionHandle, uiHMACKeyBits, uiKeyEncAlgID, uiKEKIndex, ucEncedKey, &uiEncedKeyLength, &hKeyHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GenerateKeyWithKEK returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_CalculateMAC(hSessionHandle, hKeyHandle, uiMACAlgID, NULL, ucData, uiDataLength, ucMAC, &uiMACLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_CalculateMAC return 0x%X\n", ret);
		return -1;
	}

	if (uiMACLength != 32) {
	}

	SDF_DestroyKey(hSessionHandle, hKeyHandle);
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int SM3WithoutID(void)
{
    void* hSession = NULL;
    void *hDeviceHandle = NULL;
    unsigned char data[] = {0xFA,0x77,0xDF,0xC1,0x74,0x30,0x2E,0x09,
                            0x61,0x2A,0x7D,0xB0,0x1B,0xD3,0x32,0xDD};
    unsigned char hash[] = {0xC4, 0xED, 0xB5, 0xCC, 0x63, 0xCA, 0x34, 0xC0, 0x38, 0x7A, 0x04,
                            0xCE, 0x61, 0xEF, 0x20, 0x4D, 0xFF, 0x96, 0x68, 0x58, 0xE2, 0x5A,
                            0x88, 0xA8, 0xCD, 0xD8, 0x2B, 0xF8, 0x47, 0x72, 0x09, 0x56};

    unsigned char res[32];
    unsigned int  resLen = sizeof(res);
    TEST(SDF_OpenDevice, &hDeviceHandle);
    TEST(SDF_OpenSession, hDeviceHandle, &hSession);
    TEST(SDF_HashInit, hSession, SGD_SM3, NULL, NULL, 0);
    TEST(SDF_HashUpdate, hSession, data, sizeof(data));
    TEST(SDF_HashFinal, hSession, res, &resLen);

    if (resLen != sizeof(hash) || memcmp(res, hash, resLen))
    {
        printf("hash result error\n");
        return -1;
    }

    printf("SM3WithoutID, OK\n");
    SDF_CloseSession(hSession);
	SDF_CloseDevice(hDeviceHandle);
    return 1;
}

// SM3带ID
static int SM3WithID(void)
{
    void* hSession = NULL;
    void *hDeviceHandle = NULL;
    unsigned char x[]  = {0x58, 0x8D, 0x77, 0xF3, 0x2B, 0xB6, 0x1F, 0x19, 0xF3, 0x11, 0x15,
                         0x5E, 0x32, 0x7B, 0x97, 0xFB, 0x3D, 0x03, 0x13, 0x7D, 0x59, 0x45,
                         0xE7, 0x32, 0xB8, 0x72, 0x33, 0xF3, 0x20, 0x1C, 0xF3, 0x3C};
    unsigned char y[]  = {0x7B, 0x42, 0xE9, 0x09, 0xA9, 0x3C, 0x5F, 0xE5, 0xFC, 0x1B, 0xA5,
                         0x1B, 0x9F, 0x87, 0x88, 0xAF, 0xE4, 0xDF, 0x5D, 0x87, 0xF8, 0xB6,
                         0xE6, 0x19, 0x70, 0xD6, 0x97, 0xEC, 0xB6, 0xDA, 0x7D, 0x69};
    unsigned char id[] = {0xFB,0xFD,0x00,0x14,0x2F,0x37,0x1B,0x3B,
                         0xDC,0x8A,0x1C,0x09,0x24,0x17,0x10,0xD9};
    unsigned char data[] = {0xC3,0xAE,0xFA,0x7F,0xF0,0x54,0x9E,0x49,
                            0xEF,0xBA,0xBC,0xAA,0x95,0xBA,0x06,0xAE};
    unsigned char hash[] = {0x3F, 0xC3, 0x1C, 0xAC, 0x91, 0x78, 0x81, 0x21, 0x19, 0x12, 0x89,
                            0x6D, 0x19, 0x4D, 0x7A, 0x0D, 0xFF, 0x3D, 0x8D, 0xE6, 0x5F, 0x42,
                            0x79, 0x9F, 0xED, 0xBB, 0x88, 0x86, 0xA3, 0xAA, 0x22, 0x6F};

    unsigned char   res[32];
    unsigned int    resLen = sizeof(res);
    ECCrefPublicKey pubkey;
    
    memset(&pubkey, 0, sizeof(pubkey));
    pubkey.bits = 256;
    memcpy(pubkey.x + ECCref_MAX_LEN - 32, x, sizeof(x));
    memcpy(pubkey.y + ECCref_MAX_LEN - 32, y, sizeof(y));

    TEST(SDF_OpenDevice, &hDeviceHandle);
    TEST(SDF_OpenSession, hDeviceHandle, &hSession);
    TEST(SDF_HashInit, hSession, SGD_SM3, &pubkey, id, sizeof(id));
    TEST(SDF_HashUpdate, hSession, data, sizeof(data));
    TEST(SDF_HashFinal, hSession, res, &resLen);

    if (resLen != sizeof(hash) || memcmp(res, hash, resLen))
    {
        printf("hash result error\n");
        return -1;
    }

    printf("SM3WithID, OK\n");
    
    SDF_CloseSession(hSession);
	SDF_CloseDevice(hDeviceHandle);
return 1;
}

// static int HmacWithKey(void)
// {
//     unsigned char key[16]={0};
//     unsigned int key_length = sizeof(key);
//     unsigned char in[256]={0};
//     unsigned int in_length = sizeof(in);
//     unsigned char hmac[256]={0};
//     unsigned int hmac_length = sizeof(hmac);
//     void* hSession = 0;

//     TEST(SDF_GenerateRandom, hSession, key_length, key);
//     TEST(SDF_GenerateRandom, hSession, in_length, in);
//     TEST(SM3_CalculateMAC, hSession, SGD_SM3, key, key_length, in, in_length, hmac, &hmac_length);
//     return 1;
// }

// static int HmacWithKeyIndex(void)
// {
//     unsigned int keyIndex = 1;
//     unsigned char in[256]={0};
//     unsigned int in_length = sizeof(in);
//     unsigned char hmac[256]={0};
//     unsigned int hmac_length = sizeof(hmac);
//     void* hSession = 0;

//     TEST(SDF_GenerateRandom, hSession, in_length, in);
//     TEST(SDF_HMAC_Init, hSession, SGD_SM3, keyIndex, NULL, 0);
//     TEST(SDF_HMAC_Update, hSession, in, in_length);
//     TEST(SDF_HMAC_Final, hSession, hmac, &hmac_length);
//     return 1;
// }

int main(void)
{

	if (SDF_LoadLibrary("/home/hjc/GmSSL/build/bin/libsoft_sdf.so", NULL) != SDR_OK) {
		error_print();
		goto err;
	}
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

	if (SM3_Hash() != 1) goto err;
	if (SM3_Hash_Z() != 1) goto err;
	if (SM3_CalculateMAC() != 1) goto err;
    if (SM3WithoutID() != 1) goto err;
    if (SM3WithID() != 1) goto err;
    // if (HmacWithKey() != 1) goto err;
    // if (HmacWithKeyIndex() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}