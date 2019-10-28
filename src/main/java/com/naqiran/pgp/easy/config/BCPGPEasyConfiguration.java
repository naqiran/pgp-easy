package com.naqiran.pgp.easy.config;

import lombok.Builder;
import lombok.Data;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;

@Data
public class BCPGPEasyConfiguration {
    public static BCPGPEasyEncrypt.BCPGPEasyEncryptBuilder encrypt() {
        return new BCPGPEasyEncrypt.BCPGPEasyEncryptBuilder();
    }

    public static BCPGPEasyDecrypt.BCPGPEasyDecryptBuilder decrypt() {
        return new BCPGPEasyDecrypt.BCPGPEasyDecryptBuilder();
    }

    @Data
    @Builder
    public static class BCPGPEasyEncrypt {
        @Builder.Default
        private boolean armor = true;

        /**
         * Defualt Value is PGPEncryptedData.AES_128
         */
        @Builder.Default
        private int encryptionAlgorithm = PGPEncryptedData.AES_128;

        /**
         * Defualt Value is PGPEncryptedData.AES_128
         */
        @Builder.Default
        private int compressionType = PGPCompressedData.ZLIB;

        @Builder.Default
        private boolean integrityCheck = true;
        private String recipient;
        private String fileName;
        private String keyFileName;
        private String outputFileName;

        public String getOutputFileName() {
            return outputFileName != null && outputFileName.length() > 0 ? outputFileName : fileName.replaceAll(".pgp", "");
        }
    }

    @Data
    @Builder
    public static class BCPGPEasyDecrypt {
        @Builder.Default
        private boolean armor = true;
        private String passphrase;
        private String fileName;
        private String keyFileName;
        private String outputFileName;

        public String getOutputFileName() {
            return outputFileName != null && outputFileName.length() > 0 ? outputFileName : fileName + ".pgp";
        }
    }
}