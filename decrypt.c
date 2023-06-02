#include <openssl/evp.h>
#include <stdio.h>

#define BUFFER_SIZE 4096
int decryptFile(const char *inputFile, const char *outputFile, const unsigned char* key, const unsigned char *iv) {
    FILE *inFile = fopen(inputFile, "rb");
    FILE *outFile = fopen(outputFile, "wb");

    if (inFile == NULL || outFile == NULL) {
        perror("Failed to open file");
        return 0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inBuffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char outBuffer[BUFFER_SIZE];
    int bytesRead, bytesWritten, finalBytesWritten;

    while ((bytesRead = fread(inBuffer, 1, BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH, inFile)) > 0) {
        EVP_DecryptUpdate(ctx, outBuffer, &bytesWritten, inBuffer, bytesRead);
        fwrite(outBuffer, 1, bytesWritten, outFile);
    }

    EVP_DecryptFinal_ex(ctx, outBuffer, &finalBytesWritten);
    fwrite(outBuffer, 1, finalBytesWritten, outFile);

    EVP_CIPHER_CTX_free(ctx);
    fclose(inFile);
    fclose(outFile);

    return 1;
}

int main() {
    const char *encryptedFile = "encrypted.bin";
    const char *decryptedFile = "decrypted.txt";

    // Key and IV (Initialization Vector) for AES-256 CBC
    unsigned char key[] = "01234567890123456789012345678901";
    unsigned char iv[] = "0123456789012345";

    // Dencrypt the file
    if (!decryptFile(encryptedFile,decryptedFile, key, iv)) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }
    printf("File decrypted: %s\n",decryptedFile);
    return 0;
}
