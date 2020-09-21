#pragma once
#pragma comment(lib, "bcrypt.lib")

#include <windows.h>


/// <summary>
/// 
/// </summary>
/// <param name="hCryptKey"></param>
/// <param name="provider"></param>
/// <param name="publicKey"></param>
/// <param name="pubSize"></param>
/// <param name="privateKey"></param>
/// <param name="privSize"></param>
/// <returns></returns>
BOOL CryptoInitialize(IN OUT HCRYPTKEY* hCryptKey, IN OUT HCRYPTPROV* provider, IN OUT PUCHAR* publicKey, IN OUT PULONG pubSize, IN OUT PUCHAR* privateKey, IN OUT PULONG privSize);


/// <summary>
/// 
/// </summary>
/// <param name="PublicKeyBlob"></param>
/// <param name="PublicKeySize"></param>
/// <param name="CipherText"></param>
/// <param name="CipherTextLength"></param>
/// <param name="PlainText"></param>
/// <param name="PtLen"></param>
/// <param name="pszAlgId"></param>
/// <returns></returns>
BOOL EncryptData(IN PUCHAR PublicKeyBlob, IN ULONG PublicKeySize, OUT PUCHAR* CipherText, PULONG CipherTextLength, PUCHAR PlainText, ULONG PtLen, IN LPCWSTR pszAlgId);


/// <summary>
/// 
/// </summary>
/// <param name="hKey"></param>
/// <param name="PublicKeyBlob"></param>
/// <param name="pubSize"></param>
/// <param name="PrivateKeyBlob"></param>
/// <param name="privSize"></param>
/// <returns></returns>
BOOL CryptoDestroy(IN HCRYPTKEY hKey, PUCHAR PublicKeyBlob, ULONG pubSize, PUCHAR PrivateKeyBlob, ULONG privSize);

/// <summary>
/// 
/// </summary>
/// <param name="PrivateKeyBlob"></param>
/// <param name="PrivateKeySize"></param>
/// <param name="DecryptedText"></param>
/// <param name="DecryptedTextLength"></param>
/// <param name="CipherText"></param>
/// <param name="CipherTextLength"></param>
/// <param name="pszAlgId"></param>
/// <returns></returns>
BOOL DecryptData(IN PUCHAR PrivateKeyBlob, IN ULONG PrivateKeySize, OUT IN PUCHAR* DecryptedText, OUT IN PULONG DecryptedTextLength, IN PUCHAR CipherText, IN ULONG CipherTextLength, IN LPCWSTR pszAlgId);


