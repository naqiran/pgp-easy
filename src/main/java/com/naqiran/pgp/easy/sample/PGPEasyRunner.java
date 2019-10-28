package com.naqiran.pgp.easy.sample;

import com.naqiran.pgp.easy.PGPDecryptor;
import com.naqiran.pgp.easy.PGPEncryptor;
import com.naqiran.pgp.easy.config.BCPGPEasyConfiguration;
import com.naqiran.pgp.easy.config.BCPGPEasyConfiguration.BCPGPEasyEncrypt;
import com.naqiran.pgp.easy.config.BCPGPEasyConfiguration.BCPGPEasyDecrypt;

public class PGPEasyRunner {
    public static void main(final String[] args) {
        encrypt();
        decrypt();
    }

    public static void encrypt() {
        BCPGPEasyEncrypt encryptConfiguration = BCPGPEasyConfiguration
                .encrypt()
                .fileName("test.txt")
                .keyFileName("key.asc")
                .build();
        PGPEncryptor.encrypt(encryptConfiguration);
    }

    public static void decrypt() {
        BCPGPEasyDecrypt decryptConfiguration = BCPGPEasyConfiguration.decrypt()
                .fileName("test.txt.pgp")
                .keyFileName("key.asc")
                .outputFileName("test.txt")
                .build();
        PGPDecryptor.decrypt(decryptConfiguration);
    }
}
