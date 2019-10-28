# Simple Bouncy Castle PGP Encryptor and Decryptor
 
# Encrypt:
```java
BCPGPEasyEncrypt encryptConfiguration = BCPGPEasyConfiguration.encrypt()
                .builder()
                .armor(true)
                .encryptionAlgorithm(PGPEncryptedData.AES_128)
                .encryptionAlgorithm(PGPCompressedData.ZLIB)
                .recipient("recipient")
                .fileName("test.txt")
                .keyFileName("key.asc")
                .outputFileName("test.txt.pgp")
                .build();
        PGPEncryptor.encrypt(encryptConfiguration);
```
# Decrypt:
```java
BCPGPEasyDecrypt decryptConfiguration = BCPGPEasyConfiguration.decrypt()
                .builder()
                .armor(true)
                .passphrase("passphrase")
                .fileName("test.txt.pgp")
                .keyFileName("key.asc")
                .outputFileName("test.txt")
                .build();
        PGPDecryptor.decrypt(decryptConfiguration);
```    
