package com.naqiran.pgp.easy.config;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class BCPGPEasyConfiguration {
    private boolean encrypt;
    private boolean armor;
    private int encryptionAlgorithm;
    private int compressionType;
    private boolean integrityCheck;
    private String recipient;
    private String fileName;
    private String outputFileName;
    private String keyFileName;
    private String keyId;
    private String passphrase;
}
