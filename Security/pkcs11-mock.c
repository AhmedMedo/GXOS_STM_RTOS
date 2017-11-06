/*
 *  Copyright 2011-2016 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */


#include "pkcs11-mock.h"
#include "sha256.h"
#include "TI_aes_128.h"
#include "DES.h"
#include "bigdigits.h"
#include "bigdigitsRand.h"

#define MOD_SIZE 32
//	const CK_BYTE modulus[] = {0x0A, 0x66, 0x79, 0x1D, 0xC6, 0x98, 0x81, 0x68,
//	   		   			0xDE, 0x7A, 0xB7, 0x74, 0x19, 0xBB, 0x7F, 0xB0,
//	   		   			0xC0, 0x01, 0xC6, 0x27, 0x10, 0x27, 0x00, 0x75,
//	   		   			0x14, 0x29, 0x42, 0xE1, 0x9A, 0x8D, 0x8C, 0x51,
//	   		   			0xD0, 0x53, 0xB3, 0xE3, 0x78, 0x2A, 0x1D, 0xE5,
//	   		   			0xDC, 0x5A, 0xF4, 0xEB, 0xE9, 0x94, 0x68, 0x17,
//	   		   			0x01, 0x14, 0xA1, 0xDF, 0xE6, 0x7C, 0xDC, 0x9A,
//	   		   			0x9A, 0xF5, 0x5D, 0x65, 0x56, 0x20, 0xBB, 0xAB,};
//	   		  const  	CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
//	   		const   	CK_BYTE privateExponent[] = {0x01, 0x23, 0xC5, 0xB6, 0x1B, 0xA3, 0x6E, 0xDB,
//	   		   			0x1D, 0x36, 0x79, 0x90, 0x41, 0x99, 0xA8, 0x9E,
//	   		   			0xA8, 0x0C, 0x09, 0xB9, 0x12, 0x2E, 0x14, 0x00,
//	   		   			0xC0, 0x9A, 0xDC, 0xF7, 0x78, 0x46, 0x76, 0xD0,
//	   		   			0x1D, 0x23, 0x35, 0x6A, 0x7D, 0x44, 0xD6, 0xBD,
//	   		   			0x8B, 0xD5, 0x0E, 0x94, 0xBF, 0xC7, 0x23, 0xFA,
//	   		   			0x87, 0xD8, 0x86, 0x2B, 0x75, 0x17, 0x76, 0x91,
//	   		   			0xC1, 0x1D, 0x75, 0x76, 0x92, 0xDF, 0x88, 0x81,};
      	  	  	  	  	  	  /* key 1 */
//	const CK_BYTE modulus[] = {0xd0,0xb7,0x50,0xc8,0x55,0x4b,0x64,0xc7,0xa9,0xd3,0x4d,0x06,0x8e,0x02,0x0f,0xb5,0x2f,
//			0xea,0x1b,0x39,0xc4,0x79,0x71,0xa3,0x59,0xf0,0xee,0xc5,0xda,0x04,0x37,0xea,0x3f,0xc9,0x45,0x97,0xd8,0xdb,0xff,0x54,0x44,0xf6,0xce,0x5a,0x32,0x93,0xac,
//			0x89,0xb1,0xee,0xbb,0x3f,0x71,0x2b,0x3a,0xd6,0xa0,0x63,0x86,0xe6,0x40,0x19,0x85,0xe1,0x98,0x98,0x71,0x5b,0x1e,0xa3,0x2a,0xc0,0x34,0x56,0xfe,0x17,0x96,
//			0xd3,0x1e,0xd4,0xaf,0x38,0x9f,0x4f,0x67,0x5c,0x23,0xc4,0x21,0xa1,0x25,0x49,0x1e,0x74,0x0f,0xda,0xc4,0x32,0x2e,0xc2,0xd4,0x6e,0xc9,0x45,0xdd,0xc3,0x49,0x22,0x7b,0x49,0x21,0x91,0xc9,0x04,
//			0x91,0x45,0xfb,0x2f,0x8c,0x29,0x98,0xc4,0x86,0xa8,0x40,0xea,0xc4,0xd3};
//	   		  const  	CK_BYTE publicExponent[] = {0x85,0x9e,0x49,0x9b,0x8a,0x18,0x6c,0x8e,0xe6,0x19,0x69,0x54,0x17,0x0e,0xb8,0x06,0x85,0x93,0xf0,0xd7,0x64,0x15,0x0a,0x6d,0x2e,0x5d,0x3f,0xea,0x7d,0x9d,0x0d,0x33,0xac,0x55,0x3e,0xec,0xd5,0xc3,0xf2,0x7a,0x31,0x01,0x15,0xd2,0x83,0xe4,0x93,0x77,0x82,0x01,0x95,0xc8,0xe6,0x77,0x81,0xb6,0xf1,0x12,0xa6,0x25,0xb1,0x4b,0x74,0x7f,0xa4,0xcc,0x13,0xd0,0x6e,0xba,0x09,0x17,0x24,0x6c,0x77,0x5f,0x5c,0x73,0x28,0x65,0x70,0x1a,0xe9,0x34,0x9e,0xa8,0x72,0x9c,0xde,0x0b,0xba,0xde,0x38,0x20,0x4e,0x63,0x35,0x9a,0x46,0xe6,0x72,0xa8,0xd0,0xa2,0xfd,0x53,0x00,0x69};
//	   		const   	CK_BYTE privateExponent[] = {0x27,0xb7,0x11,0x9a,0x09,0xed,0xb8,0x27,0xc1,0x34,0x18,0xc8,0x20,0xb5,0x22,0xa1,0xee,0x08,0xde,0x0e,0x4b,0xb2,0x81,0x06,0xdb,0x6b,0xb9,0x14,0x98,0xa3,0xb3,0x61,0xab,0x29,0x3a,0xf8,0x3f,0xef,0xcd,0xd8,0xa6,0xbd,0x21,0x34,0xca,0x4a,0xfa,0xcf,0x64,0xa0,0xe3,0x3c,0x01,0x4f,0x48,0xf4,0x75,0x30,0xf8,0x84,0x7c,0xc9,0x18,0x5c,0xbe,0xde,0xc0,0xd9,0x23,0x8c,0x8f,0x1d,0x54,0x98,0xf7,0x1c,0x7c,0x0c,0xff,0x48,0xdc,0x21,0x34,0x21,0x74,0x2e,0x34,0x35,0x0c,0xa9,0x40,0x07,0x75,0x3c,0xc0,0xe5,0xa7,0x83,0x26,0x4c,0xf4,0x9f,0xf6,0x44,0xff,0xea,0x94,0x25,0x3c,0xfe,0x86,0x85,
//	   				0x9a,0xcd,0x2a,0x22,0x76,0xca,0x4e,0x72,0x15,0xf8,0xeb,0xaa,0x2f,0x18,0x8f,0x51};
							/*key 1*/
								/*key 2*/
	const CK_BYTE modulus[] = {0xc8,0x88,0x3f,0x05,0x73,0xe9,0xa5,0xf5,0x12,0xfb,0x65,0xed,0x0a,0xdf,0x26,0x49,0xb0,0x32,0x37,0xed,0xf4,0xfa,0xa6,0xb2,0x59,0xf8,0x9d,0x7e,0xd5,0x9d,0x30,0xd6,0xfe,0x05,0x2e,0xf8,0xdd,0x68,0xc9,0xd6,0x72,0xc9,0xac,0x4d,0xdb,0x1e,0xdc,0xf0,0x10,0x2b,0x82,0x14,0xdb,0xd8,0x47,0x8c,0x7c,0x87,0xdf,0xca,0x0a,0xd2,0x6c,0xf5,0xa9,0xf7,0x37,0x01,0xe8,0x52,0x5e,0x05,0x9d,0x1b,0xe2,0xc5,0x68,0xb4,0x2e,0x39,0xd0,0x54,0x9b,0xb7,0x72,0xed,0x43,0x13,0x5a,0x39,0xc7,0x90,0x71,0xb7,0x6e,0x66,0x04,0xa0,0x55,0x23,0xbe,0x68,0xff,0xa9,0xb1,0xc2,0x8f,0x37,0xf3,0x0b,0xdb,0x0b,0xf7,0x8d,0xdd,0x85,0xda,0xff,0x70,0x54,0xc9,0xab,0x47,0x1b,0xb4,0x83,0xa0,0x65};
	   		  const  	CK_BYTE publicExponent[] = {0xa9,0xe9,0xdf,0x5a,0x55,0xfe,0x9e,0xec,0xcd,0x16,0xfd,0x65,0x1c,0x2d,0x7f,0x13,0xa9,0x94,0x2e,0x74,0x18,0x05,0x2b,0x4a,0xe1,0xb9,0x8f,0x8c,0xa3,0xf3,0xe8,0x28,0x53,0x2a,0x45,0x32,0x89,0xbd,0x47,0xb3,0x63,0x73,0x8f,0x86,0x6d,0xeb,0xf0,0x42,0x22,0xab,0xee,0xca,0xc1,0xe1,0x1f,0x98,0x0b,0x6f,0x11,0x5f,0x09,0x7f,0x45,0x40,0xaa,0x77,0x35,0xb9,0x93,0xf1,0x7f,0x55,0x08,0x3c,0xae,0xb6,0xa8,0x0f,0x80,0xd0,0x92,0xc5,0x9d,0x2f,0x89,0x5f,0x78,0x3f,0xab,0x56,0xa3,0x53,0xb5,0x8a,0x8c,0x43,0x16,0xea,0xcf,0x30,0x12,0xc7,0x7e,0x6f,0xbf,0xdb,0x4b,0xe7};
	   		const   	CK_BYTE privateExponent[] = {0x03,0x2e,0xd7,0xf3,0x8d,0xb0,0xa3,0xf0,0x26,0xaa,0x85,0xf3,0x5c,0x88,0x35,0xd8,0xad,0xd5,0x2e,0x62,0xf6,0x31,0xd5,0xa9,0x9a,0x6b,0x6f,0xe4,0x07,0xc3,0x71,0x1d,0xc4,0x29,0xcb,0x58,0x46,0xb4,0x0f,0xe5,0x60,0xfd,0x82,0xb1,0x8a,0x83,0xba,0xd2,0x12,0x09,0x38,0x25,0x84,0xe6,0x35,0xec,0x21,0xb3,0x82,0x99,0xd1,0x65,0x17,0x97,0x24,0x6d,0x69,0xcb,0xc0,0xe2,0x3e,0x67,0x4c,0xe7,0x0a,0x90,0x51,0x09,0x58,0x3a,0x5b,0x2e,0xc8,0x7b,0x0d,0xe7,0x62,0x59,0x4c,0x81,0x3f,0x89,0xc0,0x6d,0x3e,0xe2,0xa1,0x9b,0xfa,0x0f,0xfd,0x78,0xc2,0x6b,0xb2,0x9d,0x42,0x6f,0x76,0x47,0x02,0x04,0x34,0x34,0x1b,0x47,0x35,0xa2,0x97,0x2b,0x6a,0xa6,0x53,0xc6,0x62,0xd7,0x10,0xe7};

DIGIT_T n[MOD_SIZE], e[MOD_SIZE], d[MOD_SIZE],m[MOD_SIZE];
SHA256_CTX ctx;
CK_ATTRIBUTE_PTR pkey_Template;
CK_MECHANISM_PTR pmechanism;
CK_OBJECT_HANDLE hkey[16];
CK_OBJECT_HANDLE key_1[8];
CK_OBJECT_HANDLE key_2[8];
CK_OBJECT_HANDLE key_3[8];
//CK_OBJECT_HANDLE des_key[8];
des_ctx dc1; // Key schedule structure
//CK_BYTE_PTR pdata;
//CK_BYTE_PTR pencrypteddata;
CK_BBOOL pkcs11_mock_initialized = CK_FALSE;
CK_BBOOL pkcs11_mock_session_opened = CK_FALSE;
CK_ULONG pkcs11_mock_session_state = CKS_RO_PUBLIC_SESSION;
PKCS11_MOCK_CK_OPERATION pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
CK_OBJECT_HANDLE pkcs11_mock_find_result = CKR_OBJECT_HANDLE_INVALID;
CK_UTF8CHAR  userpin[20]="\0";
CK_UTF8CHAR so_pin[]="DrAymanBahaa";


CK_FUNCTION_LIST pkcs11_mock_functions = 
{
	{2, 20},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent
};


CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	if (CK_TRUE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	IGNORE(pInitArgs);

	pkcs11_mock_initialized = CK_TRUE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	IGNORE(pReserved);

	pkcs11_mock_initialized = CK_FALSE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	pInfo->cryptokiVersion.major = 0x02;
	pInfo->cryptokiVersion.minor = 0x14;
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_MOCK_CK_INFO_MANUFACTURER_ID, strlen(PKCS11_MOCK_CK_INFO_MANUFACTURER_ID));
	pInfo->flags = 0;
	memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
	memcpy(pInfo->libraryDescription, PKCS11_MOCK_CK_INFO_LIBRARY_DESCRIPTION, strlen(PKCS11_MOCK_CK_INFO_LIBRARY_DESCRIPTION));
	pInfo->libraryVersion.major = PKCS11_MOCK_CK_INFO_LIBRARY_VERSION_MAJOR;
	pInfo->libraryVersion.minor = PKCS11_MOCK_CK_INFO_LIBRARY_VERSION_MINOR;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (NULL == ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &pkcs11_mock_functions;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	IGNORE(tokenPresent);

	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pSlotList)
	{
		*pulCount = 1;
	}
	else
	{
		if (0 == *pulCount)
			return CKR_BUFFER_TOO_SMALL;

		pSlotList[0] = PKCS11_MOCK_CK_SLOT_ID;
		*pulCount = 1;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
	memcpy(pInfo->slotDescription, PKCS11_MOCK_CK_SLOT_INFO_SLOT_DESCRIPTION, strlen(PKCS11_MOCK_CK_SLOT_INFO_SLOT_DESCRIPTION));
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_MOCK_CK_SLOT_INFO_MANUFACTURER_ID, strlen(PKCS11_MOCK_CK_SLOT_INFO_MANUFACTURER_ID));
	pInfo->flags = CKF_TOKEN_PRESENT;
	pInfo->hardwareVersion.major = 0x01;
	pInfo->hardwareVersion.minor = 0x00;
	pInfo->firmwareVersion.major = 0x01;
	pInfo->firmwareVersion.minor = 0x00;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	memset(pInfo->label, ' ', sizeof(pInfo->label));
	memcpy(pInfo->label, PKCS11_MOCK_CK_TOKEN_INFO_LABEL, strlen(PKCS11_MOCK_CK_TOKEN_INFO_LABEL));
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_MOCK_CK_TOKEN_INFO_MANUFACTURER_ID, strlen(PKCS11_MOCK_CK_TOKEN_INFO_MANUFACTURER_ID));
	memset(pInfo->model, ' ', sizeof(pInfo->model));
	memcpy(pInfo->model, PKCS11_MOCK_CK_TOKEN_INFO_MODEL, strlen(PKCS11_MOCK_CK_TOKEN_INFO_MODEL));
	memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
	memcpy(pInfo->serialNumber, PKCS11_MOCK_CK_TOKEN_INFO_SERIAL_NUMBER, strlen(PKCS11_MOCK_CK_TOKEN_INFO_SERIAL_NUMBER));
	pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
	pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulSessionCount = (CK_TRUE == pkcs11_mock_session_opened) ? 1 : 0;
	pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulRwSessionCount = ((CK_TRUE == pkcs11_mock_session_opened) && ((CKS_RO_PUBLIC_SESSION != pkcs11_mock_session_state) || (CKS_RO_USER_FUNCTIONS != pkcs11_mock_session_state))) ? 1 : 0;
	pInfo->ulMaxPinLen = PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN;
	pInfo->ulMinPinLen = PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->hardwareVersion.major = 0x01;
	pInfo->hardwareVersion.minor = 0x00;
	pInfo->firmwareVersion.major = 0x01;
	pInfo->firmwareVersion.minor = 0x00;
	memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pMechanismList)
	{
		*pulCount = 9;
	}
	else
	{
		if (9 > *pulCount)
			return CKR_BUFFER_TOO_SMALL;

		pMechanismList[0] = CKM_RSA_PKCS_KEY_PAIR_GEN;
		pMechanismList[1] = CKM_RSA_PKCS;
		pMechanismList[2] = CKM_SHA1_RSA_PKCS;
		pMechanismList[3] = CKM_RSA_PKCS_OAEP;
		pMechanismList[4] = CKM_DES3_CBC;
		pMechanismList[5] = CKM_DES3_KEY_GEN;
		pMechanismList[6] = CKM_SHA_1;
		pMechanismList[7] = CKM_XOR_BASE_AND_DATA;
		pMechanismList[8] = CKM_AES_CBC;

		*pulCount = 9;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	switch (type)
	{
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = 1024;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;

		case CKM_RSA_PKCS:
			pInfo->ulMinKeySize = 1024;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_SIGN_RECOVER | CKF_VERIFY | CKF_VERIFY_RECOVER | CKF_WRAP | CKF_UNWRAP;
			break;

		case CKM_SHA1_RSA_PKCS:
			pInfo->ulMinKeySize = 1024;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;

		case CKM_RSA_PKCS_OAEP:
			pInfo->ulMinKeySize = 1024;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;

		case CKM_DES3_CBC:
			pInfo->ulMinKeySize = 192;
			pInfo->ulMaxKeySize = 192;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;

		case CKM_DES3_KEY_GEN:
			pInfo->ulMinKeySize = 192;
			pInfo->ulMaxKeySize = 192;
			pInfo->flags = CKF_GENERATE;
			break;

		case CKM_SHA_1:
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_DIGEST;
			break;

		case CKM_XOR_BASE_AND_DATA:
			pInfo->ulMinKeySize = 128;
			pInfo->ulMaxKeySize = 256;
			pInfo->flags = CKF_DERIVE;
			break;

		case CKM_AES_CBC:
			pInfo->ulMinKeySize = 128;
			pInfo->ulMaxKeySize = 256;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulPinLen < PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulPinLen > PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	if (NULL == pLabel)
		return CKR_ARGUMENTS_BAD;

	if (CK_TRUE == pkcs11_mock_session_opened)
		return CKR_SESSION_EXISTS;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	return CKR_OK;
	int i=0;
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (CKS_RW_SO_FUNCTIONS != pkcs11_mock_session_state)
		return CKR_USER_NOT_LOGGED_IN;

	if (NULL == pPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulPinLen < PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulPinLen > PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;
	//puserpin= (CK_UTF8CHAR *)malloc(ulPinLen);
//	for(i;i<(ulPinLen/sizeof(CK_UTF8CHAR));i++)
//	{
//		puserpin[i]=pPin[i];
//	}
	strcpy(userpin,pPin);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((CKS_RO_PUBLIC_SESSION == pkcs11_mock_session_state) || (CKS_RO_USER_FUNCTIONS == pkcs11_mock_session_state))
		return CKR_SESSION_READ_ONLY;

	if (NULL == pOldPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulOldLen < PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulOldLen > PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	if (NULL == pNewPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulNewLen < PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulNewLen > PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;
	if( pkcs11_mock_session_state == CKS_RW_USER_FUNCTIONS)
	{
		if(strcmp(userpin,pOldPin)==0)
			strcpy(userpin,pNewPin);
		else
			return CKR_PIN_INCORRECT;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (CK_TRUE == pkcs11_mock_session_opened)
		return CKR_SESSION_COUNT;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	IGNORE(pApplication);

	IGNORE(Notify);

	if (NULL == phSession)
		return CKR_ARGUMENTS_BAD;

	pkcs11_mock_session_opened = CK_TRUE;
	pkcs11_mock_session_state = (flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
	*phSession = PKCS11_MOCK_CK_SESSION_ID;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	pkcs11_mock_session_opened = CK_FALSE;
	pkcs11_mock_session_state = CKS_RO_PUBLIC_SESSION;
	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	pkcs11_mock_session_opened = CK_FALSE;
	pkcs11_mock_session_state = CKS_RO_PUBLIC_SESSION;
	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	pInfo->slotID = PKCS11_MOCK_CK_SLOT_ID;
	pInfo->state = pkcs11_mock_session_state;
	pInfo->flags = CKF_SERIAL_SESSION;
	if ((pkcs11_mock_session_state != CKS_RO_PUBLIC_SESSION) && (pkcs11_mock_session_state != CKS_RO_USER_FUNCTIONS))
		pInfo->flags = pInfo->flags | CKF_RW_SESSION;
	pInfo->ulDeviceError = 0;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulOperationStateLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pOperationState)
	{
		*pulOperationStateLen = 256;
	}
	else
	{
		if (256 > *pulOperationStateLen)
			return CKR_BUFFER_TOO_SMALL;

		memset(pOperationState, 1, 256);
		*pulOperationStateLen = 256;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pOperationState)
		return CKR_ARGUMENTS_BAD;

	if (256 != ulOperationStateLen)
		return CKR_ARGUMENTS_BAD;

	IGNORE(hEncryptionKey);

	IGNORE(hAuthenticationKey);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv = CKR_OK;
	return rv;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((CKU_SO != userType) && (CKU_USER != userType))
		return CKR_USER_TYPE_INVALID;

	if (NULL == pPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulPinLen < PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulPinLen > PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	switch (pkcs11_mock_session_state)
	{
		case CKS_RO_PUBLIC_SESSION:

			if (CKU_SO == userType)
				rv = CKR_SESSION_READ_ONLY_EXISTS;
			else
			{
				if(userpin=="\0")
					return CKR_USER_PIN_NOT_INITIALIZED;
				else if(strcmp(userpin,pPin)== 0)
				pkcs11_mock_session_state = CKS_RO_USER_FUNCTIONS;
				else
					return CKR_PIN_INCORRECT;


			}
			break;

		case CKS_RO_USER_FUNCTIONS:
		case CKS_RW_USER_FUNCTIONS:

			rv = (CKU_SO == userType) ? CKR_USER_ANOTHER_ALREADY_LOGGED_IN : CKR_USER_ALREADY_LOGGED_IN;

			break;

		case CKS_RW_PUBLIC_SESSION:
			if(userType == CKU_SO)
			{
				if(strcmp(so_pin,pPin)==0)
					pkcs11_mock_session_state =CKS_RW_SO_FUNCTIONS;

				else
					return CKR_PIN_INCORRECT;
			}
			else
			{
				if(userpin=="\0")
									return CKR_USER_PIN_NOT_INITIALIZED;
								else if(strcmp(userpin,pPin)== 0)
								pkcs11_mock_session_state = CKS_RW_USER_FUNCTIONS;
								else
									return CKR_PIN_INCORRECT;
			}

			break;

		case CKS_RW_SO_FUNCTIONS:

			rv = (CKU_SO == userType) ? CKR_USER_ALREADY_LOGGED_IN : CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

			break;
	}

	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
	return CKR_OK;
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((pkcs11_mock_session_state == CKS_RO_PUBLIC_SESSION) || (pkcs11_mock_session_state == CKS_RW_PUBLIC_SESSION))
		return CKR_USER_NOT_LOGGED_IN;
	if(pkcs11_mock_session_state > 1)
		pkcs11_mock_session_state = CKS_RW_PUBLIC_SESSION;
	else
		pkcs11_mock_session_state = CKS_RO_PUBLIC_SESSION;

}


CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phObject)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulCount; i++)
	{
		if (NULL == pTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}
	if(*(CK_OBJECT_CLASS *)pTemplate[0].pValue==CKO_PUBLIC_KEY)

	{
		*phObject = PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY;
	}
	else if(*(CK_OBJECT_CLASS *)pTemplate[0].pValue==CKO_PRIVATE_KEY)
	{
		*phObject =PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY;
	}
	else if(*(CK_OBJECT_CLASS *)pTemplate[0].pValue==CKO_SECRET_KEY)
	{
		*phObject = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;
	}
	pkey_Template=pTemplate;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject)
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == phNewObject)
		return CKR_ARGUMENTS_BAD;

	if ((NULL != pTemplate) && (0 >= ulCount))
	{
		for (i = 0; i < ulCount; i++)
		{
			if (NULL == pTemplate[i].pValue)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			if (0 >= pTemplate[i].ulValueLen)
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	*phNewObject = PKCS11_MOCK_CK_OBJECT_HANDLE_DATA;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hObject))
		return CKR_OBJECT_HANDLE_INVALID;

	pkey_Template=NULL_PTR;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hObject))
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == pulSize)
		return CKR_ARGUMENTS_BAD;

	*pulSize = PKCS11_MOCK_CK_OBJECT_SIZE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hObject))
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulCount)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulCount; i++)
	{
		if (CKA_LABEL == pTemplate[i].type)
		{
			if (NULL != pTemplate[i].pValue)
			{
				if (pTemplate[i].ulValueLen < strlen(PKCS11_MOCK_CK_OBJECT_CKA_LABEL))
					return CKR_BUFFER_TOO_SMALL;
				else
					memcpy(pTemplate[i].pValue, PKCS11_MOCK_CK_OBJECT_CKA_LABEL, strlen(PKCS11_MOCK_CK_OBJECT_CKA_LABEL));
			}

			pTemplate[i].ulValueLen = strlen(PKCS11_MOCK_CK_OBJECT_CKA_LABEL);
		}
		else if (CKA_VALUE == pTemplate[i].type)
		{
			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY == hObject)
			{
				pTemplate[i].ulValueLen = (CK_ULONG) -1;
			}
			else
			{
				if (NULL != pTemplate[i].pValue)
				{
					if (pTemplate[i].ulValueLen < strlen(PKCS11_MOCK_CK_OBJECT_CKA_VALUE))
						return CKR_BUFFER_TOO_SMALL;
					else
						memcpy(pTemplate[i].pValue, PKCS11_MOCK_CK_OBJECT_CKA_VALUE, strlen(PKCS11_MOCK_CK_OBJECT_CKA_VALUE));
				}

				pTemplate[i].ulValueLen = strlen(PKCS11_MOCK_CK_OBJECT_CKA_VALUE);
			}
		}
		else
		{
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hObject))
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulCount)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulCount; i++)
	{
		if ((CKA_LABEL == pTemplate[i].type) || (CKA_VALUE == pTemplate[i].type))
		{
			if (NULL == pTemplate[i].pValue)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			if (0 >= pTemplate[i].ulValueLen)
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else
		{
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_ULONG i = 0;
	CK_ULONG_PTR cka_class_value = NULL;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation)
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	IGNORE(ulCount);

	pkcs11_mock_find_result = CK_INVALID_HANDLE;

	for (i = 0; i < ulCount; i++)
	{
		if (NULL == pTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (CKA_CLASS == pTemplate[i].type)
		{
			if (sizeof(CK_ULONG) != pTemplate[i].ulValueLen)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			cka_class_value = (CK_ULONG_PTR) pTemplate[i].pValue;

			switch (*cka_class_value)
			{
				case CKO_DATA:
					pkcs11_mock_find_result = PKCS11_MOCK_CK_OBJECT_HANDLE_DATA;
					break;
				case CKO_SECRET_KEY:
					pkcs11_mock_find_result = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;
					break;
				case CKO_PUBLIC_KEY:
					pkcs11_mock_find_result = PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY;
					break;
				case CKO_PRIVATE_KEY:
					pkcs11_mock_find_result = PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY;
					break;
			}
		}
	}

	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_FIND;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_FIND != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((NULL == phObject) && (0 < ulMaxObjectCount))
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulObjectCount)
		return CKR_ARGUMENTS_BAD;

	switch (pkcs11_mock_find_result)
	{
		case PKCS11_MOCK_CK_OBJECT_HANDLE_DATA:
			
			if (ulMaxObjectCount >= 2)
			{
				phObject[0] = pkcs11_mock_find_result;
				phObject[1] = pkcs11_mock_find_result;
			}

			*pulObjectCount = 2;

			break;

		case CK_INVALID_HANDLE:
			
			*pulObjectCount = 0;

			break;

		default:

			if (ulMaxObjectCount >= 1)
			{
				phObject[0] = pkcs11_mock_find_result;
			}

			*pulObjectCount = 1;

			break;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_FIND != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE_PTR hKey)
{
	unsigned int i=0;
	 pmechanism= pMechanism;

	 //hkey=hKey;
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

//	if ((PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation) &&
//		(PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation) &&
//		(PKCS11_MOCK_CK_OPERATION_SIGN != pkcs11_mock_active_operation))
//		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	 if(pMechanism->mechanism == CKM_RSA_PKCS)
	 	{
		 if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != *hKey)
		 				return CKR_KEY_TYPE_INCONSISTENT;
		 			mpConvFromOctets(n, MOD_SIZE, modulus, sizeof( modulus));
		 			mpConvFromOctets(e, MOD_SIZE, publicExponent, sizeof(publicExponent));
		 			mpConvFromOctets(d, MOD_SIZE,privateExponent, sizeof(privateExponent));
	 	}
	 	else if(pMechanism->mechanism ==CKM_DES_CBC)
	 	{
	 		if ((NULL == pMechanism->pParameter) || (8 != pMechanism->ulParameterLen))
	 						return CKR_MECHANISM_PARAM_INVALID;

	 		//			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
	 		//				return CKR_KEY_TYPE_INCONSISTENT;
	 					Des_Key(&dc1, hKey, ENDE ); // Sets up key schedule for Encryption and Decryption


	 	}
	 	else if(pMechanism->mechanism ==CKM_DES3_CBC)
	 	{
	 		if ((NULL == pMechanism->pParameter) || (8 != pMechanism->ulParameterLen))
	 						return CKR_MECHANISM_PARAM_INVALID;

	 		//			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
	 		//				return CKR_KEY_TYPE_INCONSISTENT;
	 					for(i;i<24;i++)
	 					{
	 						if(i<8)
	 							key_1[i]=hKey[i];
	 						else if(i>=8 && i<16)
	 							key_2[i-8]=hKey[i];
	 						else if(i>16)
	 							key_3[i-16]=hKey[i];
	 					}

	 	}
	 	else if(pMechanism->mechanism ==CKM_AES_CBC)
	 	{
	 					if ((NULL == pMechanism->pParameter) || (16 != pMechanism->ulParameterLen))
	 						return CKR_MECHANISM_PARAM_INVALID;

	 					//if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
	 						//return CKR_KEY_TYPE_INCONSISTENT;
	 					 for(i;i<16;i++)
	 					   {
	 						 hkey[i] = hKey[i];
	 					   }
	 	}
	 	else
	 	{
	 		return CKR_MECHANISM_INVALID;
	 	}
//	switch (pMechanism->mechanism)
//	{
//		case CKM_RSA_PKCS:
//
//
//
//			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != *hKey)
//				return CKR_KEY_TYPE_INCONSISTENT;
////			    mpConvFromOctets(n, MOD_SIZE,pMechanism->Rsa_object->pmodulus, sizeof(pMechanism->Rsa_object->pmodulus));
////				mpConvFromOctets(e, MOD_SIZE, pMechanism->Rsa_object->pPublicExponent, sizeof(pMechanism->Rsa_object->pPublicExponent));
////				mpConvFromOctets(d, MOD_SIZE, pMechanism->Rsa_object->pPrivateExponent, sizeof(pMechanism->Rsa_object->pPrivateExponent));
//			mpConvFromOctets(n, MOD_SIZE, modulus, sizeof( modulus));
//			mpConvFromOctets(e, MOD_SIZE, publicExponent, sizeof(publicExponent));
//			mpConvFromOctets(d, MOD_SIZE,privateExponent, sizeof(privateExponent));
//
//			break;
//
//		case CKM_RSA_PKCS_OAEP:
//
//			if ((NULL == pMechanism->pParameter) || (sizeof(CK_RSA_PKCS_OAEP_PARAMS) != pMechanism->ulParameterLen))
//				return CKR_MECHANISM_PARAM_INVALID;
//
//			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hKey)
//				return CKR_KEY_TYPE_INCONSISTENT;
//
//			break;
//
//		case CKM_DES_CBC:
//
//			if ((NULL == pMechanism->pParameter) || (8 != pMechanism->ulParameterLen))
//				return CKR_MECHANISM_PARAM_INVALID;
//
////			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
////				return CKR_KEY_TYPE_INCONSISTENT;
//			Des_Key(&dc1, hKey, ENDE ); // Sets up key schedule for Encryption and Decryption
//
//			break;
//		case CKM_DES3_CBC:
//
//			if ((NULL == pMechanism->pParameter) || (8 != pMechanism->ulParameterLen))
//				return CKR_MECHANISM_PARAM_INVALID;
//
////			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
////				return CKR_KEY_TYPE_INCONSISTENT;
//			for(i;i<24;i++)
//			{
//				if(i<8)
//					key_1[i]=hKey[i];
//				else if(i>=8 && i<16)
//					key_2[i-8]=hKey[i];
//				else if(i>16)
//					key_3[i-16]=hKey[i];
//			}
//			break;
//
//		case CKM_AES_CBC:
//
//			if ((NULL == pMechanism->pParameter) || (16 != pMechanism->ulParameterLen))
//				return CKR_MECHANISM_PARAM_INVALID;
//
//			//if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
//				//return CKR_KEY_TYPE_INCONSISTENT;
//			 for(i;i<16;i++)
//			   {
//				 hkey[i] = hKey[i];
//			   }
//			break;
//
//		default:
//
//			return CKR_MECHANISM_INVALID;
//	}
//
//	switch (pkcs11_mock_active_operation)
//	{
//		case PKCS11_MOCK_CK_OPERATION_NONE:
//			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_ENCRYPT;
//			break;
//		case PKCS11_MOCK_CK_OPERATION_DIGEST:
//			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT;
//			break;
//		case PKCS11_MOCK_CK_OPERATION_SIGN:
//			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT;
//			break;
//		default:
//			return CKR_FUNCTION_FAILED;
//	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	pkcs11_mock_active_operation=PKCS11_MOCK_CK_OPERATION_ENCRYPT;
	CK_ULONG i = 0;
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_ENCRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pEncryptedData)
	{
		switch (pkcs11_mock_active_operation)
		{
			case PKCS11_MOCK_CK_OPERATION_ENCRYPT:
				if(pmechanism->mechanism == CKM_AES_CBC)
				{
					pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
					aes_CBCe(pData,  hkey,pmechanism->pParameter,1);
				}
				else if(pmechanism->mechanism == CKM_DES_CBC)
				{
					DES_Enc_CBC(&dc1, pData, 1,pmechanism->pParameter); //Encrypt Data, Result is stored back into Data
				//	DES_Dec_CBC(&dc1, pData, 1,IV);
				}
				else if(pmechanism->mechanism == CKM_DES3_CBC)
				{
					 CBCe(&dc1,pData,pmechanism->pParameter,1, key_1,key_2,key_3);
				}
				//rsa
				else if(pmechanism->mechanism == CKM_RSA_PKCS)
				{
					mpConvFromOctets(m, MOD_SIZE, pData, ulDataLen);
//					mpModExp(m, m, d, n, MOD_SIZE);
					mpModExp(m, m, e, n, MOD_SIZE);
					mpConvToOctets(m, MOD_SIZE,pEncryptedData,ulDataLen);
				}
				break;
			case PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST;
				break;
			case PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN;
				break;
			default:
				return CKR_FUNCTION_FAILED;
		}
		/*if (ulDataLen > *pulEncryptedDataLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}*/
	//	else

//			for (i = 0; i < ulDataLen; i++)
//				pEncryptedData[i] = pData[i] ^ 0xAB;

//			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
//			aes_CBCe(pData, hkey,pmechanism->pParameter, 1);

	}

	*pulEncryptedDataLen = ulDataLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_ULONG i = 0;
	pkcs11_mock_active_operation=PKCS11_MOCK_CK_OPERATION_ENCRYPT;
//	if (CK_FALSE == pkcs11_mock_initialized)
//		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_ENCRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

//	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
//		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 > ulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pEncryptedPart)
	{
		if (ulPartLen > *pulEncryptedPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			switch (pkcs11_mock_active_operation)
			{
				case PKCS11_MOCK_CK_OPERATION_ENCRYPT:
					if(pmechanism->mechanism == CKM_AES_CBC)
					{
						pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
						aes_CBCe(pPart,  hkey,pmechanism->pParameter,ulPartLen);
					}
					else if(pmechanism->mechanism == CKM_DES_CBC)
					{
						DES_Enc_CBC(&dc1, pPart, ulPartLen,pmechanism->pParameter);
						pkcs11_mock_active_operation=PKCS11_MOCK_CK_OPERATION_NONE;
					}
					else if(pmechanism->mechanism == CKM_DES3_CBC)
					{
						CBCe(&dc1,pPart,pmechanism->pParameter,ulPartLen,key_1,key_2,key_3);
					}
					//rsa
					break;
				    case PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT:
						pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST;
						break;
					case PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT:
						pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN;
						break;
					default:
						return CKR_FUNCTION_FAILED;
					}
		}
//		else
//		{
////			for (i = 0; i < ulPartLen; i++)
////				pEncryptedPart[i] = pPart[i] ^ 0xAB;
//			aes_CBCe(pPart,  hkey,pmechanism->pParameter,ulPartLen);
//		}
	}

	*pulEncryptedPartLen = ulPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	pkcs11_mock_active_operation =PKCS11_MOCK_CK_OPERATION_ENCRYPT;
//	if (CK_FALSE == pkcs11_mock_initialized)
//		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_ENCRYPT != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT != pkcs11_mock_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

//	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
//		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulLastEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pLastEncryptedPart)
	{
		switch (pkcs11_mock_active_operation)
		{
			case PKCS11_MOCK_CK_OPERATION_ENCRYPT:
				//pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
				switch (pkcs11_mock_active_operation)
				{
					case PKCS11_MOCK_CK_OPERATION_ENCRYPT:
						if(pmechanism->mechanism == CKM_AES_CBC)
						{
							pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
							aes_CBCe(pLastEncryptedPart,  hkey,pmechanism->pParameter,1);
						}
						else if(pmechanism->mechanism == CKM_DES_CBC)
						{
							DES_Enc_CBC(&dc1, pLastEncryptedPart, 1,pmechanism->pParameter);
							pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
						}
						else if(pmechanism->mechanism == CKM_DES3_CBC)
						{
							CBCe(&dc1,pLastEncryptedPart,pmechanism->pParameter,1,key_1,key_2,key_3);
						}
						//rsa
						break;
						case PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT:
							pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST;
							break;
						case PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT:
							pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN;
							break;
						default:
							return CKR_FUNCTION_FAILED;
				}
				break;
			case PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST;
				break;
			case PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN;
				break;
			default:
				return CKR_FUNCTION_FAILED;
		}
	}

	*pulLastEncryptedPartLen = 0;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE_PTR hKey)
{
	CK_ULONG i = 0;
	pmechanism= pMechanism;
//	if (CK_FALSE == pkcs11_mock_initialized)
//		return CKR_CRYPTOKI_NOT_INITIALIZED;

//	if ((PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation) &&
//		(PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation) &&
//		(PKCS11_MOCK_CK_OPERATION_VERIFY != pkcs11_mock_active_operation))
//		return CKR_OPERATION_ACTIVE;

//	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
//		return CKR_SESSION_HANDLE_INVALID;
//
//	if (NULL == pMechanism)
//		return CKR_ARGUMENTS_BAD;


	if(pMechanism->mechanism == CKM_RSA_PKCS)
	{
		if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != *hKey)
						return CKR_KEY_TYPE_INCONSISTENT;
						mpConvFromOctets(n, MOD_SIZE, modulus, sizeof( modulus));
						mpConvFromOctets(e, MOD_SIZE, publicExponent, sizeof(publicExponent));
						mpConvFromOctets(d, MOD_SIZE,privateExponent, sizeof(privateExponent));
	}
	else if(pMechanism->mechanism ==CKM_DES_CBC)
	{
		if ((NULL == pMechanism->pParameter) || (8 != pMechanism->ulParameterLen))
								return CKR_MECHANISM_PARAM_INVALID;
							 Des_Key(&dc1, hKey, ENDE ); // Sets up key schedule for Encryption and Decryption

						//	if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
							//	return CKR_KEY_TYPE_INCONSISTENT;
	}
	else if(pMechanism->mechanism ==CKM_DES3_CBC)
	{
//		if ((NULL == pMechanism->pParameter) || (8 != pMechanism->ulParameterLen))
//						return CKR_MECHANISM_PARAM_INVALID;

		//			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
		//				return CKR_KEY_TYPE_INCONSISTENT;
					for(i;i<24;i++)
								{
									if(i<8)
										key_1[i]=hKey[i];
									else if(i>=8 && i<16)
										key_2[i-8]=hKey[i];
									else if(i>=16)
										key_3[i-16]=hKey[i];
								}

	}
	else if(pMechanism->mechanism ==CKM_AES_CBC)
	{
		if ((NULL == pMechanism->pParameter) || (16 != pMechanism->ulParameterLen))
						return CKR_MECHANISM_PARAM_INVALID;

				//	if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
				//		return CKR_KEY_TYPE_INCONSISTENT;

					for(i;i<16;i++)
					hkey[i] = hKey[i];
	}
	else
	{
		return CKR_MECHANISM_INVALID;
	}
//	switch (pMechanism->mechanism)
//	{
//		case CKM_RSA_PKCS:
//
//
//			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != *hKey)
//				return CKR_KEY_TYPE_INCONSISTENT;
//						mpConvFromOctets(n, MOD_SIZE, modulus, sizeof( modulus));
//						mpConvFromOctets(e, MOD_SIZE, publicExponent, sizeof(publicExponent));
//						mpConvFromOctets(d, MOD_SIZE,privateExponent, sizeof(privateExponent));
//
//			break;
//
//		case CKM_RSA_PKCS_OAEP:
//
//			if ((NULL == pMechanism->pParameter) || (sizeof(CK_RSA_PKCS_OAEP_PARAMS) != pMechanism->ulParameterLen))
//				return CKR_MECHANISM_PARAM_INVALID;
//
//			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hKey)
//				return CKR_KEY_TYPE_INCONSISTENT;
//
//			break;
//		case CKM_DES_CBC:
//
//					if ((NULL == pMechanism->pParameter) || (8 != pMechanism->ulParameterLen))
//						return CKR_MECHANISM_PARAM_INVALID;
//					 Des_Key(&dc1, hKey, ENDE ); // Sets up key schedule for Encryption and Decryption
//
//				//	if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
//					//	return CKR_KEY_TYPE_INCONSISTENT;
//			break;
//
//		case CKM_DES3_CBC:
//
//			if ((NULL == pMechanism->pParameter) || (8 != pMechanism->ulParameterLen))
//				return CKR_MECHANISM_PARAM_INVALID;
//
////			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
////				return CKR_KEY_TYPE_INCONSISTENT;
//			for(i;i<24;i++)
//						{
//							if(i<8)
//								key_1[i]=hKey[i];
//							else if(i>=8 && i<16)
//								key_2[i-8]=hKey[i];
//							else if(i>=16)
//								key_3[i-16]=hKey[i];
//						}
//
//			break;
//
//		case CKM_AES_CBC:
//
//			if ((NULL == pMechanism->pParameter) || (16 != pMechanism->ulParameterLen))
//				return CKR_MECHANISM_PARAM_INVALID;
//
//		//	if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
//		//		return CKR_KEY_TYPE_INCONSISTENT;
//
//			for(i;i<16;i++)
//			hkey[i] = hKey[i];
//
//			break;
//
//		default:
//
//			return CKR_MECHANISM_INVALID;
//	}

//	switch (pkcs11_mock_active_operation)
//	{
//		case PKCS11_MOCK_CK_OPERATION_NONE:
//			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT;
//			break;
//		case PKCS11_MOCK_CK_OPERATION_DIGEST:
//			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST;
//			break;
//		case PKCS11_MOCK_CK_OPERATION_VERIFY:
//			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY;
//			break;
//		default:
//			return CKR_FUNCTION_FAILED;
//	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	  pkcs11_mock_active_operation=PKCS11_MOCK_CK_OPERATION_DECRYPT;
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DECRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pEncryptedData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulEncryptedDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pData)
	{
		if (ulEncryptedDataLen > *pulDataLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
//			for (i = 0; i < ulEncryptedDataLen; i++)
//				pData[i] = pEncryptedData[i] ^ 0xAB;
			switch (pkcs11_mock_active_operation)
									{
										case PKCS11_MOCK_CK_OPERATION_DECRYPT:
											if(pmechanism->mechanism == CKM_AES_CBC)
											{
												aes_CBCd(pEncryptedData,  hkey,pmechanism->pParameter,1);
											}
											else if(pmechanism->mechanism == CKM_DES_CBC)
											{
												DES_Dec_CBC(&dc1, pEncryptedData, 1,pmechanism->pParameter);
											}
											else if(pmechanism->mechanism == CKM_DES3_CBC)
											{
												 CBCd(&dc1,pEncryptedData,pmechanism->pParameter,1, key_1,key_2,key_3);
											}
											//rsa
											else if(pmechanism->mechanism == CKM_RSA_PKCS)
															{
																mpConvFromOctets(m, MOD_SIZE,pEncryptedData, ulEncryptedDataLen);
															mpModExp(m, m, d, n, MOD_SIZE);
												//			mpModExp(m, m, e, n, MOD_SIZE);
																mpConvToOctets(m, MOD_SIZE,pData,pulDataLen);
															}
											break;
										    case PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT:
												pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST;
												break;
											case PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT:
												pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN;
												break;
											default:
												return CKR_FUNCTION_FAILED;
											}



		}
	}

	*pulDataLen = ulEncryptedDataLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	pkcs11_mock_active_operation= PKCS11_MOCK_CK_OPERATION_DECRYPT;
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DECRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pEncryptedPart)
		return CKR_ARGUMENTS_BAD;

	if (0 > ulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pPart)
	{
//		if (ulEncryptedPartLen > *pulPartLen)
//		{
//			return CKR_BUFFER_TOO_SMALL;
//		}
		//else
		{
			switch (pkcs11_mock_active_operation)
						{
							case PKCS11_MOCK_CK_OPERATION_DECRYPT:
								if(pmechanism->mechanism == CKM_AES_CBC)
								{

									aes_CBCd(pEncryptedPart,  hkey,pmechanism->pParameter,ulEncryptedPartLen);
								}
								else if(pmechanism->mechanism == CKM_DES_CBC)
								{
									DES_Dec_CBC(&dc1,pEncryptedPart, ulEncryptedPartLen,pmechanism->pParameter);

								}
								else if(pmechanism->mechanism == CKM_DES3_CBC)
								{
									 CBCd(&dc1, pEncryptedPart,pmechanism->pParameter,ulEncryptedPartLen, key_1,key_2,key_3);
								}
								//rsa
								break;
							    case PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT:
									pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST;
									break;
								case PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT:
									pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN;
									break;
								default:
									return CKR_FUNCTION_FAILED;
								}
		}
	}

	*pulPartLen = ulEncryptedPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	pkcs11_mock_active_operation=PKCS11_MOCK_CK_OPERATION_DECRYPT;
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_DECRYPT != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY != pkcs11_mock_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulLastPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pLastPart)
	{
		switch (pkcs11_mock_active_operation)
		{
			case PKCS11_MOCK_CK_OPERATION_DECRYPT:
				if(pmechanism->mechanism == CKM_AES_CBC)
										{
											aes_CBCd(pLastPart,  hkey,pmechanism->pParameter,1);
										}
										else if(pmechanism->mechanism == CKM_DES_CBC)
										{
											DES_Dec_CBC(&dc1, pLastPart, 1,pmechanism->pParameter);
										}
										else if(pmechanism->mechanism == CKM_DES3_CBC)
										{
											CBCd(&dc1,pLastPart,pmechanism->pParameter,1, key_1,key_2,key_3);
										}
										//rsa

				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
				break;
			case PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST;
				break;
			case PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_VERIFY;
				break;
			default:
				return CKR_FUNCTION_FAILED;
		}
	}

	*pulLastPartLen = 0;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_ENCRYPT != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DECRYPT != pkcs11_mock_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_SHA256 != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	switch (pkcs11_mock_active_operation)
	{
		case PKCS11_MOCK_CK_OPERATION_NONE:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST;
			sha256_init(&ctx);
			break;
		case PKCS11_MOCK_CK_OPERATION_ENCRYPT:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT;
			break;
		case PKCS11_MOCK_CK_OPERATION_DECRYPT:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST;
			break;
		default:
			return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	//CK_BYTE hash[20] = { 0x7B, 0x50, 0x2C, 0x3A, 0x1F, 0x48, 0xC8, 0x60, 0x9A, 0xE2, 0x12, 0xCD, 0xFB, 0x63, 0x9D, 0xEE, 0x39, 0x67, 0x3F, 0x5E };

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulDigestLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pDigest)
	{
		if (sizeof(pDigest) > *pulDigestLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			//memcpy(pDigest, hash, sizeof(hash));
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
		}
	}

	//*pulDigestLen = sizeof(hash);

	return CKR_OK;
}





CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

//	if (PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation)
//		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 < ulPartLen)
		return CKR_ARGUMENTS_BAD;
	sha256_update(&ctx,pPart,strlen(pPart));
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
		return CKR_OBJECT_HANDLE_INVALID;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_BYTE hash[20] = { 0x7B, 0x50, 0x2C, 0x3A, 0x1F, 0x48, 0xC8, 0x60, 0x9A, 0xE2, 0x12, 0xCD, 0xFB, 0x63, 0x9D, 0xEE, 0x39, 0x67, 0x3F, 0x5E };

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation) && 
		(PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT != pkcs11_mock_active_operation) && 
		(PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST != pkcs11_mock_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulDigestLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pDigest)
	{
		if (sizeof(pDigest) > *pulDigestLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			memcpy(pDigest, hash, sizeof(hash));

			switch (pkcs11_mock_active_operation)
			{
				case PKCS11_MOCK_CK_OPERATION_DIGEST:
					pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
					sha256_final(&ctx,pDigest);
					break;
				case PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT:
					pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_ENCRYPT;
					break;
				case PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST:
					pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT;
					break;
				default:
					return CKR_FUNCTION_FAILED;
			}
		}
	}

	*pulDigestLen = sizeof(hash);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_ENCRYPT != pkcs11_mock_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if ((CKM_RSA_PKCS == pMechanism->mechanism) || (CKM_SHA1_RSA_PKCS == pMechanism->mechanism))
	{
		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;

		if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hKey)
			return CKR_KEY_TYPE_INCONSISTENT;
	}
	else
	{
		return CKR_MECHANISM_INVALID;
	}

	if (PKCS11_MOCK_CK_OPERATION_NONE == pkcs11_mock_active_operation)
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN;
	else
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_SIGN != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pSignature)
	{
		if (sizeof(signature) > *pulSignatureLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			memcpy(pSignature, signature, sizeof(signature));
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
		}
	}

	*pulSignatureLen = sizeof(signature);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_SIGN != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_SIGN != pkcs11_mock_active_operation) && 
		(PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT != pkcs11_mock_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pSignature)
	{
		if (sizeof(signature) > *pulSignatureLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			memcpy(pSignature, signature, sizeof(signature));

			if (PKCS11_MOCK_CK_OPERATION_SIGN == pkcs11_mock_active_operation)
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
			else
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_ENCRYPT;
		}
	}

	*pulSignatureLen = sizeof(signature);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation)
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS == pMechanism->mechanism)
	{
		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;

		if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hKey)
			return CKR_KEY_TYPE_INCONSISTENT;
	}
	else
	{
		return CKR_MECHANISM_INVALID;
	}

	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN_RECOVER;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_SIGN_RECOVER != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pSignature)
	{
		if (ulDataLen > *pulSignatureLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulDataLen; i++)
				pSignature[i] = pData[i] ^ 0xAB;

			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
		}
	}

	*pulSignatureLen = ulDataLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DECRYPT != pkcs11_mock_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if ((CKM_RSA_PKCS == pMechanism->mechanism) || (CKM_SHA1_RSA_PKCS == pMechanism->mechanism))
	{
		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;

		if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hKey)
			return CKR_KEY_TYPE_INCONSISTENT;
	}
	else
	{
		return CKR_MECHANISM_INVALID;
	}

	if (PKCS11_MOCK_CK_OPERATION_NONE == pkcs11_mock_active_operation)
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_VERIFY;
	else
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_VERIFY != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pSignature)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (sizeof(signature) != ulSignatureLen)
		return CKR_SIGNATURE_LEN_RANGE;

	if (0 != memcmp(pSignature, signature, sizeof(signature)))
		return CKR_SIGNATURE_INVALID;

	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_VERIFY != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_VERIFY != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY != pkcs11_mock_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pSignature)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (sizeof(signature) != ulSignatureLen)
		return CKR_SIGNATURE_LEN_RANGE;

	if (0 != memcmp(pSignature, signature, sizeof(signature)))
		return CKR_SIGNATURE_INVALID;

	if (PKCS11_MOCK_CK_OPERATION_VERIFY == pkcs11_mock_active_operation)
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
	else
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation)
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS == pMechanism->mechanism)
	{
		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;

		if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hKey)
			return CKR_KEY_TYPE_INCONSISTENT;
	}
	else
	{
		return CKR_MECHANISM_INVALID;
	}

	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_VERIFY_RECOVER;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_VERIFY_RECOVER != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pSignature)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pData)
	{
		if (ulSignatureLen > *pulDataLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulSignatureLen; i++)
				pData[i] = pSignature[i] ^ 0xAB;

			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
		}
	}

	*pulDataLen = ulSignatureLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pEncryptedPart)
	{
		if (ulPartLen > *pulEncryptedPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulPartLen; i++)
				pEncryptedPart[i] = pPart[i] ^ 0xAB;
		}
	}

	*pulEncryptedPartLen = ulPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pEncryptedPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pPart)
	{
		if (ulEncryptedPartLen > *pulPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulEncryptedPartLen; i++)
				pPart[i] = pEncryptedPart[i] ^ 0xAB;
		}
	}

	*pulPartLen = ulEncryptedPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pEncryptedPart)
	{
		if (ulPartLen > *pulEncryptedPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulPartLen; i++)
				pEncryptedPart[i] = pPart[i] ^ 0xAB;
		}
	}

	*pulEncryptedPartLen = ulPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pEncryptedPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pPart)
	{
		if (ulEncryptedPartLen > *pulPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulEncryptedPartLen; i++)
				pPart[i] = pEncryptedPart[i] ^ 0xAB;
		}
	}

	*pulPartLen = ulEncryptedPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_DES3_KEY_GEN != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phKey)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulCount; i++)
	{
		if (NULL == pTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	*phKey = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS_KEY_PAIR_GEN != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (NULL == pPublicKeyTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPublicKeyAttributeCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pPrivateKeyTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPrivateKeyAttributeCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phPublicKey)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phPrivateKey)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		if (NULL == pPublicKeyTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pPublicKeyTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	for (i = 0; i < ulPrivateKeyAttributeCount; i++)
	{
		if (NULL == pPrivateKeyTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pPrivateKeyTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	*phPublicKey = PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY;
	*phPrivateKey = PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	CK_BYTE wrappedKey[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hWrappingKey)
		return CKR_KEY_HANDLE_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
		return CKR_KEY_HANDLE_INVALID;

	if (NULL != pWrappedKey)
	{
		if (sizeof(wrappedKey) > *pulWrappedKeyLen)
			return CKR_BUFFER_TOO_SMALL;
		else
			memcpy(pWrappedKey, wrappedKey, sizeof(wrappedKey));
	}

	*pulWrappedKeyLen = sizeof(wrappedKey);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hUnwrappingKey)
		return CKR_KEY_HANDLE_INVALID;

	if (NULL == pWrappedKey)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulWrappedKeyLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulAttributeCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phKey)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulAttributeCount; i++)
	{
		if (NULL == pTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	*phKey = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_XOR_BASE_AND_DATA != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL == pMechanism->pParameter) || (sizeof(CK_KEY_DERIVATION_STRING_DATA) != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hBaseKey)
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == phKey)
		return CKR_ARGUMENTS_BAD;

	if ((NULL != pTemplate) && (0 >= ulAttributeCount))
	{
		for (i = 0; i < ulAttributeCount; i++)
		{
			if (NULL == pTemplate[i].pValue)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			if (0 >= pTemplate[i].ulValueLen)
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	*phKey = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pSeed)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSeedLen)
		return CKR_ARGUMENTS_BAD;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	DIGIT_T a[8];
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == RandomData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulRandomLen)
		return CKR_ARGUMENTS_BAD;

	memset(RandomData, 1, ulRandomLen);
	mpRandomBits( a, 8, ulRandomLen*8);
	mpConvToOctets(a, 8,RandomData,ulRandomLen);


	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;
	
	return CKR_FUNCTION_NOT_PARALLEL;
}


CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;
	
	return CKR_FUNCTION_NOT_PARALLEL;
}


CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((0 != flags)  && (CKF_DONT_BLOCK != flags))
		return CKR_ARGUMENTS_BAD;

	if (NULL == pSlot)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pReserved)
		return CKR_ARGUMENTS_BAD;

	return CKR_NO_EVENT;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetUnmanagedStructSizeList)(CK_ULONG_PTR pSizeList, CK_ULONG_PTR pulCount)
{
	CK_ULONG sizes[] = {
		sizeof(CK_ATTRIBUTE),
		sizeof(CK_C_INITIALIZE_ARGS),
		sizeof(CK_FUNCTION_LIST),
		sizeof(CK_INFO),
		sizeof(CK_MECHANISM),
		sizeof(CK_MECHANISM_INFO),
		sizeof(CK_SESSION_INFO),
		sizeof(CK_SLOT_INFO),
		sizeof(CK_TOKEN_INFO),
		sizeof(CK_VERSION),
		sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS),
		sizeof(CK_AES_CTR_PARAMS),
		sizeof(CK_ARIA_CBC_ENCRYPT_DATA_PARAMS),
		sizeof(CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS),
		sizeof(CK_CAMELLIA_CTR_PARAMS),
		sizeof(CK_CMS_SIG_PARAMS),
		sizeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS),
		sizeof(CK_ECDH1_DERIVE_PARAMS),
		sizeof(CK_ECDH2_DERIVE_PARAMS),
		sizeof(CK_ECMQV_DERIVE_PARAMS),
		sizeof(CK_EXTRACT_PARAMS),
		sizeof(CK_KEA_DERIVE_PARAMS),
		sizeof(CK_KEY_DERIVATION_STRING_DATA),
		sizeof(CK_KEY_WRAP_SET_OAEP_PARAMS),
		sizeof(CK_KIP_PARAMS),
		sizeof(CK_MAC_GENERAL_PARAMS),
		sizeof(CK_OTP_PARAM),
		sizeof(CK_OTP_PARAMS),
		sizeof(CK_OTP_SIGNATURE_INFO),
		sizeof(CK_PBE_PARAMS),
		sizeof(CK_PKCS5_PBKD2_PARAMS),
		sizeof(CK_RC2_CBC_PARAMS),
		sizeof(CK_RC2_MAC_GENERAL_PARAMS),
		sizeof(CK_RC2_PARAMS),
		sizeof(CK_RC5_CBC_PARAMS),
		sizeof(CK_RC5_MAC_GENERAL_PARAMS),
		sizeof(CK_RC5_PARAMS),
		sizeof(CK_RSA_PKCS_OAEP_PARAMS),
		sizeof(CK_RSA_PKCS_PSS_PARAMS),
		sizeof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS),
		sizeof(CK_SKIPJACK_RELAYX_PARAMS),
		sizeof(CK_SSL3_KEY_MAT_OUT),
		sizeof(CK_SSL3_KEY_MAT_PARAMS),
		sizeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS),
		sizeof(CK_SSL3_RANDOM_DATA),
		sizeof(CK_TLS_PRF_PARAMS),
		sizeof(CK_WTLS_KEY_MAT_OUT),
		sizeof(CK_WTLS_KEY_MAT_PARAMS),
		sizeof(CK_WTLS_MASTER_KEY_DERIVE_PARAMS),
		sizeof(CK_WTLS_PRF_PARAMS),
		sizeof(CK_WTLS_RANDOM_DATA),
		sizeof(CK_X9_42_DH1_DERIVE_PARAMS),
		sizeof(CK_X9_42_DH2_DERIVE_PARAMS),
		sizeof(CK_X9_42_MQV_DERIVE_PARAMS),
	};

	CK_ULONG sizes_count = sizeof(sizes) / sizeof(CK_ULONG);

	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pSizeList)
	{
		*pulCount = sizes_count;
	}
	else
	{
		if (sizes_count > *pulCount)
			return CKR_BUFFER_TOO_SMALL;

		memcpy(pSizeList, sizes, sizeof(sizes));
		*pulCount = sizes_count;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EjectToken)(CK_SLOT_ID slotID)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InteractiveLogin)(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_OK;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	switch (pkcs11_mock_session_state)
	{
		case CKS_RO_PUBLIC_SESSION:

			pkcs11_mock_session_state = CKS_RO_USER_FUNCTIONS;

			break;

		case CKS_RO_USER_FUNCTIONS:
		case CKS_RW_USER_FUNCTIONS:

			rv = CKR_USER_ALREADY_LOGGED_IN;

			break;

		case CKS_RW_PUBLIC_SESSION:

			pkcs11_mock_session_state = CKS_RW_USER_FUNCTIONS;

			break;

		case CKS_RW_SO_FUNCTIONS:

			rv = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

			break;
	}

	return rv;
}
