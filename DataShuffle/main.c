#include "Shuffle.h"
#include <stdio.h>

int main()
{
	HCRYPTPROV hCryptoProvider = 0;
	HCRYPTKEY hCryptoKey = 0;
	PUCHAR CipherText = NULL;
	ULONG CipherTextLength = 0;
	PUCHAR publicKey = 0;
	PUCHAR privateKey = 0;
	ULONG privSize = 0;
	ULONG pubSize = 0;
	PUCHAR PlainText = "\nThis is my plain text data with some more data on top of it\nHere is some more stuff to addgohome\n";
	SIZE_T PtLen = strlen(PlainText);
	PUCHAR DecryptedText = NULL;
	ULONG DecryptedSize = 0;
	// Init the crypto 
	BOOL status = CryptoInitialize(&hCryptoKey, &hCryptoProvider, &publicKey,&pubSize, &privateKey,  &privSize);
	if (status == FALSE)
		return 1;
	// Just for view
	printf("\n------Start Public Key------\n");
	for (ULONG i = 0; i < pubSize; i++)
		printf("%c", publicKey[i]);
    printf("\n--------END Public Key--------\n");

	printf("\n------Start Private Key------\n");
	for (ULONG i = 0; i < privSize; i++)
		printf("%c", privateKey[i]);
	printf("\n--------END Private Key--------\n");

	//
	BOOL status1 = EncryptData(publicKey, pubSize, &CipherText, &CipherTextLength, PlainText, PtLen, BCRYPT_RSA_ALGORITHM);
	// 
	DecryptData(privateKey, privSize, &DecryptedText, &DecryptedSize, CipherText, CipherTextLength,  BCRYPT_RSA_ALGORITHM);
	//DecryptData(NULL, privSize, &DecryptedText, &DecryptedSize, CipherText, CipherTextLength, BCRYPT_RSA_ALGORITHM);
	printf("\nDecryptedData: <%s>\n", DecryptedText);
	CryptoDestroy(hCryptoKey,  publicKey, pubSize, privateKey, privSize);
	HeapFree(GetProcessHeap(), 0, DecryptedText);
	HeapFree(GetProcessHeap(), 0, CipherText);
	
	return 0;

}
