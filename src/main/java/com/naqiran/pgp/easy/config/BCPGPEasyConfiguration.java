package com.naqiran.pgp.easy.config;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
public class BCPGPEasyConfiguration {
    public static BCPGPEasyEncrypt encrypt() {
        return new BCPGPEasyEncrypt();
    }

    public static BCPGPEasyDecrypt decrypt() {
        return new BCPGPEasyDecrypt();
    }

    @Data
    @Builder
    @NoArgsConstructor
    public static class BCPGPEasyEncrypt {
        private boolean armor;
        private int encryptionAlgorithm;
        private int compressionType;
        private boolean integrityCheck;
        private String recipient;
        private String fileName;
        private String keyFileName;
        private String outputFileName;
    }

    @Data
    @Builder
    @NoArgsConstructor
    public static class BCPGPEasyDecrypt {
        private boolean armor;
        private String passphrase;
        private String fileName;
        private String keyFileName;
        private String outputFileName;
    }
}