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
	PUCHAR PlainText = "This is my plain text data with some more data on top of it";
	SIZE_T PtLen = strlen(PlainText);
	PUCHAR DecryptedText = NULL;
	ULONG DecryptedSize = 0;
	BOOL status = CryptoInitialize(&hCryptoKey, &hCryptoProvider, &publicKey,&pubSize, &privateKey,  &privSize);
	if (status == FALSE)
		return 1;
	for (int i = 0; privSize >= i; i++)
	{
		printf("%c", privateKey[i]);
	}
	BCRYPT_RSAKEY_BLOB *pub = (BCRYPT_RSAKEY_BLOB*)&publicKey;
	BCRYPT_RSAKEY_BLOB* priv = (BCRYPT_RSAKEY_BLOB*)&privateKey;
	BOOL status1 = EncryptData(publicKey, pubSize, &CipherText, &CipherTextLength, PlainText, PtLen, BCRYPT_RSA_ALGORITHM);
	DecryptData(privateKey, privSize, &DecryptedText, &DecryptedSize, CipherText, CipherTextLength,  BCRYPT_RSA_ALGORITHM);
	printf("DecryptedData: <%s>\n", DecryptedText);
	return 0;

}