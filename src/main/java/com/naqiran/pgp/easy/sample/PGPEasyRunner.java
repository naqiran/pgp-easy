package com.naqiran.pgp.easy.sample;

import com.naqiran.pgp.easy.PGPDecryptor;
import com.naqiran.pgp.easy.PGPEncryptor;
import com.naqiran.pgp.easy.config.BCPGPEasyConfiguration;
import com.naqiran.pgp.easy.config.BCPGPEasyConfiguration.BCPGPEasyEncrypt;
import com.naqiran.pgp.easy.config.BCPGPEasyConfiguration.BCPGPEasyDecrypt;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;

public class PGPEasyRunner {
    public static void main(final String[] args) {
        encrypt();
        decrypt();
    }

    public static void encrypt() {
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
    }

    public static void decrypt() {
        BCPGPEasyDecrypt decryptConfiguration = BCPGPEasyConfiguration.decrypt()
                .builder()
                .armor(true)
                .passphrase("passphrase")
                .fileName("test.txt.pgp")
                .keyFileName("key.asc")
                .outputFileName("test.txt")
                .build();
        PGPDecryptor.decrypt(decryptConfiguration);
    }
}
