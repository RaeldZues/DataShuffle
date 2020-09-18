#include "Shuffle.h"

/// <summary>
/// <para>- Open the algorithm provider </para>
/// <para>- Create a key pair CSP Blob </para>
/// <para>- Set the key pair properties, if any</para>
/// <para>- Finalize the key pair </para>
/// <para>- Close the algorith provider </para>
/// </summary>
/// <param name="pKeyHandle"></param>
/// <param name="pszAlgId"></param>
/// <param name="dwLength"></param>
/// <returns></returns>
static BOOL GenKeyHandle(OUT BCRYPT_KEY_HANDLE* pKeyHandle, IN LPCWSTR pszAlgId, IN DWORD dwLength)
{
	BCRYPT_ALG_HANDLE hAlgorithm = INVALID_HANDLE_VALUE;
	BOOL retVal = TRUE;
	// TODO: add a option for the algorithm to be provided to the genkeys func as a passthrough
	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, MS_PRIMITIVE_PROVIDER, 0)))
	{
		retVal = FALSE;
	}
	// Create empty key pair CSP Blob
	if (!NT_SUCCESS(BCryptGenerateKeyPair(hAlgorithm, pKeyHandle, dwLength, 0)))
	{
		// Close up shop cleanly
		// Intentionally left blank for dbg printing later.
		if (!NT_SUCCESS(BCryptCloseAlgorithmProvider(hAlgorithm, 0)))
		{
			retVal = FALSE;
		}
		retVal = FALSE;
	}
	// Set properties
	// TODO: Figure out if I need any properties or not

	// Finalize the key
	if (!NT_SUCCESS(BCryptFinalizeKeyPair(*pKeyHandle, 0)))
	{
		retVal = FALSE;
	}
	// Cleanup of the algorithm provider
	if (!NT_SUCCESS(BCryptCloseAlgorithmProvider(hAlgorithm, 0)))
	{
		retVal = FALSE;
	}
	return retVal;
}


/// <summary>
/// <para>- Aquire context of the provider</para>
/// <para>- Export public and private keys</para>
/// </summary>
/// <param name="hCryptKey"></param>
/// <param name="provider"></param>
/// <param name="publicKey"></param>
/// <param name="pubSize"></param>
/// <param name="privateKey"></param>
/// <param name="privSize"></param>
/// <returns></returns>
BOOL CryptoInitialize(IN OUT HCRYPTKEY* hCryptKey, IN OUT HCRYPTPROV* provider, IN OUT PUCHAR* publicKey, IN OUT PULONG pubSize, IN OUT PUCHAR* privateKey, IN OUT PULONG privSize)
{
	BCRYPT_KEY_HANDLE pKeyHandle = INVALID_HANDLE_VALUE;
	DWORD length = 4096;
	BOOL status = GenKeyHandle(&pKeyHandle, BCRYPT_RSA_ALGORITHM, length);
	if (status != TRUE || INVALID_HANDLE_VALUE == pKeyHandle)
		return status;

	ULONG cbOutput = 0;

	// Public Key setup
	// Get the proper size
	if (!NT_SUCCESS(BCryptExportKey(pKeyHandle, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, pubSize, 0)))
	{
		return FALSE;
	}

	// Allocate space for the key
	*publicKey = HeapAlloc(GetProcessHeap(), 0, *pubSize * sizeof(unsigned char));
	if (!NT_SUCCESS(BCryptExportKey(pKeyHandle, NULL, BCRYPT_RSAPUBLIC_BLOB, *publicKey, *pubSize, pubSize, 0)))
	{
		return FALSE;
	}

	BCRYPT_RSAKEY_BLOB* data = (BCRYPT_RSAKEY_BLOB*)publicKey;
	// Private Key Setup
	if (!NT_SUCCESS(BCryptExportKey(pKeyHandle, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, privSize, 0)))
	{
		// TODO: Cleanup public key
		return FALSE;
	}
	*privateKey = HeapAlloc(GetProcessHeap(), 0, *privSize * sizeof(unsigned char));
	// Allocate space for the key
	if (!NT_SUCCESS(BCryptExportKey(pKeyHandle, NULL, BCRYPT_RSAPRIVATE_BLOB, *privateKey, *privSize, privSize, 0)))
	{
		// TODO: Cleanup public key
		return FALSE;
	}
	return TRUE;
}

/// <summary>
/// <para>- Open the algorithm</para>
/// <para>- Import the key you plan to use</para>
/// <para>- Close the algorithm</para>
/// <para>- Cursory encrypt call to identify size</para>
/// <para>- Allocate space for the size</para>
/// <para>- Encrypt the data</para>
/// </summary>
/// <param name="PublicKeyBlob"></param>
/// <param name="PublicKeySize"></param>
/// <param name="CipherText"></param>
/// <param name="CipherTextLength"></param>
/// <param name="PlainText"></param>
/// <param name="PtLen"></param>
/// <param name="pszAlgId"></param>
/// <returns></returns>
BOOL EncryptData(IN PUCHAR PublicKey, IN ULONG PublicKeySize, OUT PUCHAR* EncryptedBuffer, PULONG EncryptedBufferSize, PUCHAR InputData, ULONG InputDataSize, IN LPCWSTR pszAlgId)
{
	BCRYPT_ALG_HANDLE hAlgorithm = INVALID_HANDLE_VALUE;
	BOOL retVal = TRUE;
	NTSTATUS success = STATUS_UNSUCCESSFUL;
	BCRYPT_OAEP_PADDING_INFO paddingInfo = { 0 };
	paddingInfo.pszAlgId = pszAlgId;
	paddingInfo.pbLabel = NULL;
	paddingInfo.cbLabel = 0;

	// Open algorithm
	if (!NT_SUCCESS(success = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, NULL, 0)))
	{
		retVal = FALSE;
		return retVal;
	}

	// Import key pair
	BCRYPT_KEY_HANDLE hPublicKey = 0;
	if (!NT_SUCCESS(success = BCryptImportKeyPair(hAlgorithm, NULL, BCRYPT_RSAPUBLIC_BLOB, &hPublicKey, PublicKey, PublicKeySize, BCRYPT_NO_KEY_VALIDATION)))
	{
		retVal = FALSE;
		return retVal;
	}
	
	ULONG size = 0;
	// Encrypt nothing to get size
	if (!NT_SUCCESS(success = BCryptEncrypt(hPublicKey, InputData, InputDataSize, NULL, NULL,	0, NULL, 0, EncryptedBufferSize, BCRYPT_PAD_PKCS1)))
	{
		retVal = FALSE;
		return retVal;
	}
	// Allocate proper ciphertext size
	*EncryptedBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, *EncryptedBufferSize);
	if (NULL == *EncryptedBuffer)
	{
		retVal = FALSE;
		return retVal;
	}

	// Encrypt data properly
	if (!NT_SUCCESS(success = BCryptEncrypt(hPublicKey, InputData, InputDataSize, NULL, NULL, 0, *EncryptedBuffer, *EncryptedBufferSize, EncryptedBufferSize, BCRYPT_PAD_PKCS1)))
	{
		retVal = FALSE;
		return retVal;
	}
	// Close the algorithm
	if (!NT_SUCCESS(success = BCryptCloseAlgorithmProvider(hAlgorithm, 0)))
	{
		retVal = FALSE;
		return retVal;
	}
	return TRUE;
}


//DecryptData(privateKey, privSize, CipherText, CipherTextLength, &DecryptedText, &DecryptedSize, BCRYPT_RSA_ALGORITHM);

/// <summary>
/// <para>- Open the algoirthm</para>
/// <para>- Import the key you plan to use for decryption</para>
/// <para>- Close the algorithm</para>
/// <para>- Get correct size of decrypted data</para>
/// <para>- Allocate space for the buffer</para>
/// <para>- Decrypt the Ciphertext into the new buffer</para>
/// </summary>
/// <param name="PrivateKeyBlob"></param>
/// <param name="PrivateKeySize"></param>
/// <param name="CipherText"></param>
/// <param name="CipherTextLength"></param>
/// <param name="DecryptedText"></param>
/// <param name="DecryptedTextLength"></param>
/// <param name="pszAlgId"></param>
/// <returns></returns>
BOOL DecryptData(IN PUCHAR PrivateKeyBlob, IN ULONG PrivateKeySize, OUT IN PUCHAR* DecryptedText, OUT IN PULONG DecryptedTextLength, IN PUCHAR CipherText, IN ULONG CipherTextLength,  IN LPCWSTR pszAlgId)
{
	BCRYPT_ALG_HANDLE hAlgorithm = INVALID_HANDLE_VALUE;
	BOOL retVal = TRUE;
	BCRYPT_OAEP_PADDING_INFO paddingInfo = { 0 };
	paddingInfo.pszAlgId = pszAlgId;
	paddingInfo.pbLabel = NULL;
	paddingInfo.cbLabel = 0;
	NTSTATUS success = STATUS_UNSUCCESSFUL;

	// Open algorithm
	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, NULL, 0)))
	{
		retVal = FALSE;
		return retVal;
	}

	// Import key pair
	BCRYPT_KEY_HANDLE hPrivateKey = 0;
	if (!NT_SUCCESS(BCryptImportKeyPair(hAlgorithm, NULL, BCRYPT_RSAPRIVATE_BLOB, &hPrivateKey, PrivateKeyBlob, PrivateKeySize, BCRYPT_NO_KEY_VALIDATION)))
	{
		retVal = FALSE;
		return retVal;
	}
	BCRYPT_RSAKEY_BLOB* pub = (BCRYPT_RSAKEY_BLOB*)&hPrivateKey;
	
	//Get correct size of decrypted data
	
	if (!NT_SUCCESS(success = BCryptDecrypt(hPrivateKey, CipherText, CipherTextLength, NULL, NULL, 0, NULL, 0, DecryptedTextLength,	BCRYPT_PAD_PKCS1)))
	{
		retVal = FALSE;
		return retVal;
	}
	//Allocate space for the buffer
	*DecryptedText = HeapAlloc(GetProcessHeap(), 0, *DecryptedTextLength * sizeof(UCHAR));
	//Decrypt the Ciphertext into the new buffer
	if (!NT_SUCCESS(BCryptDecrypt(hPrivateKey, CipherText, CipherTextLength, NULL, NULL, 0, *DecryptedText,	*DecryptedTextLength, DecryptedTextLength, BCRYPT_PAD_PKCS1)))
	{
		retVal = FALSE;
		return retVal;
	}
	// Close the algorithm
	if (!NT_SUCCESS(BCryptCloseAlgorithmProvider(hAlgorithm, 0)))
	{
		retVal = FALSE;
		return retVal;
	}
	return TRUE;
}