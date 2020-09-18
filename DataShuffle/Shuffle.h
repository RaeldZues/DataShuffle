#pragma once
#pragma comment(lib, "bcrypt.lib")

#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

/// <summary>
/// - Aquire the context of the proivider
/// - Generate new priv/pub key pair  (Internal function to gen keys)
/// </summary>
/// <param name="hCryptKey"></param>
/// <param name="provider"></param>
/// <param name="publicKey"></param>
/// <param name="privateKey"></param>
/// <returns></returns>
BOOL CryptoInitialize(IN OUT HCRYPTKEY* hCryptKey, IN OUT HCRYPTPROV* provider, IN OUT PUCHAR* publicKey, IN OUT PULONG pubSize, IN OUT PUCHAR* privateKey, IN OUT PULONG privSize);

/// <summary>
///
/// </summary>
/// <param name="hPublicKey"></param>
/// <param name="CipherText"></param>
/// <param name="CipherTextLength"></param>
/// <param name="PlainText"></param>
/// <param name="PtLen"></param>
/// <returns></returns>
BOOL EncryptData(IN PUCHAR PublicKeyBlob, IN ULONG PublicKeySize, OUT PUCHAR* CipherText, PULONG CipherTextLength, PUCHAR PlainText, ULONG PtLen, IN LPCWSTR pszAlgId);


BOOL DecryptData(IN PUCHAR PrivateKeyBlob, IN ULONG PrivateKeySize, OUT IN PUCHAR* DecryptedText, OUT IN PULONG DecryptedTextLength, IN PUCHAR* CipherText, IN ULONG CipherTextLength,IN LPCWSTR pszAlgId);