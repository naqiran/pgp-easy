package com.naqiran.pgp.easy;

import com.naqiran.pgp.easy.config.BCPGPEasyConfiguration.BCPGPEasyDecrypt;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

import java.io.BufferedOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Iterator;

@Slf4j
public class PGPDecryptor {

    public static final String decrypt(final BCPGPEasyDecrypt configuration) {
        Security.addProvider(new BouncyCastleProvider());
        String decryptedFileName = configuration.getOutputFileName();
        try (final InputStream inputStream = PGPUtil.getDecoderStream(IOUtils.getInputStream(configuration.getFileName()))) {
            final JcaPGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory(inputStream);
            PGPEncryptedDataList encryptedDataList = null;
            Object pgpObject = pgpObjectFactory.nextObject();
            if (pgpObject instanceof PGPEncryptedDataList) {
                encryptedDataList = (PGPEncryptedDataList)pgpObject;
            } else {
                encryptedDataList = (PGPEncryptedDataList)pgpObjectFactory.nextObject();
            }
            Iterator<PGPPublicKeyEncryptedData> encryptedDataIter = encryptedDataList.getEncryptedDataObjects();
            PGPPrivateKey privateKey = null;
            PGPPublicKeyEncryptedData encryptedData = null;
            long keyId = 0;
            while (privateKey == null && encryptedDataIter.hasNext()) {
                encryptedData = encryptedDataIter.next();
                keyId = encryptedData.getKeyID();
                privateKey = getPrivateKey(keyId, configuration);
            }
            if (privateKey != null) {
                final JcaPGPObjectFactory encryptedFactory = new JcaPGPObjectFactory(encryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(new BouncyCastleProvider()).build(privateKey)));
                Object message = encryptedFactory.nextObject();
                if (message instanceof PGPCompressedData) {
                    final PGPCompressedData compressedData = (PGPCompressedData) message;
                    JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(compressedData.getDataStream());
                    message = pgpFact.nextObject();
                }
                if (message instanceof PGPLiteralData) {
                    final PGPLiteralData literalData = (PGPLiteralData) message;
                    try (OutputStream outputStream = new BufferedOutputStream(IOUtils.getOutputStream(decryptedFileName));
                         final InputStream literalStream = literalData.getInputStream()) {
                        Streams.pipeAll(literalStream, outputStream);
                    }
                    return decryptedFileName;
                }
            } else {
                log.error("No Private Key Exist to Decrypt: {} - {}", keyId, configuration.getFileName());
            }
        } catch (final Exception e) {
            log.error("Error in decrypting the file: {}", configuration.getFileName(), e);
        }
        return configuration.getOutputFileName();
    }

    public static PGPPrivateKey getPrivateKey(final long keyId, final BCPGPEasyDecrypt configuration) {
        final String keyFileName = configuration.getKeyFileName();
        try (final InputStream keyStream = IOUtils.getInputStream(keyFileName)) {
            final PGPSecretKeyRingCollection keyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyStream), new BcKeyFingerprintCalculator());
            final PGPSecretKey secretKey = keyRingCollection.getSecretKey(keyId);
            if (secretKey != null && configuration.getPassphrase() != null) {
                final PBESecretKeyDecryptor builder = new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider(new BouncyCastleProvider()).build())
                        .setProvider(new BouncyCastleProvider()).build(configuration.getPassphrase().toCharArray());
                return secretKey.extractPrivateKey(builder);
            } else {
                log.error("Secret Key is not available for Key Id: {} or Pass Phrase is not set: {}", keyId);
            }
        } catch (final PGPException pgpe) {
            log.error("PGP Error in getting the Private Key: {}", keyFileName, pgpe);
        } catch (final Exception e) {
            log.error("Error getting the Private Key: {}", keyFileName, e);
        }
        return null;
    }
}