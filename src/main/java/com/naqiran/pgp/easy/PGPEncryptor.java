package com.naqiran.pgp.easy;

import com.naqiran.pgp.easy.config.BCPGPEasyConfiguration;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

@Slf4j
public class PGPEncryptor {

    public final String encrypt(BCPGPEasyConfiguration configuration) {
        final String encryptedFileName = configuration.getOutputFileName() != null ? configuration.getOutputFileName() : configuration.getFileName() + ".pgp";
        Security.addProvider(new BouncyCastleProvider());
        final int cryptoAlgorithm = configuration.getEncryptionAlgorithm();
        final int compressionType = configuration.getCompressionType();
        try (final OutputStream outputStream = configuration.isArmor() ? new ArmoredOutputStream(IOUtils.getOutputStream(encryptedFileName)) :
                IOUtils.getOutputStream(encryptedFileName)) {
            PGPPublicKey publicKey = getPublicKey(configuration);
            if (publicKey != null) {
                JcePGPDataEncryptorBuilder builder = new JcePGPDataEncryptorBuilder(cryptoAlgorithm)
                        .setSecureRandom(new SecureRandom())
                        .setWithIntegrityPacket(configuration.isIntegrityCheck())
                        .setProvider(new BouncyCastleProvider());
                final PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(builder);
                encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider(new BouncyCastleProvider()));
                PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(compressionType);
                try (final OutputStream encryptedStream = encryptedDataGenerator.open(outputStream, new byte[1 << 16]);
                     OutputStream compressedStream = compressedDataGenerator.open(encryptedStream)) {
                    writeFileToLiteralData(compressedStream, PGPLiteralData.BINARY, configuration.getFileName(), new byte[1 << 16]);
                    return encryptedFileName;
                }
            } else {
                log.error("No Public Key found for the user");
            }
        } catch (PGPException e) {
            log.error("PGPException in encrypting the file: {}", e);
        } catch (Exception e) {
            log.error("Error in encrypting the file: {}", e);
        }
        return null;
    }

    public static PGPPublicKey getPublicKey(final BCPGPEasyConfiguration configuration) {
        final String keyFileName = configuration.getKeyFileName();
        try (final InputStream keyStream = IOUtils.getInputStream(keyFileName)) {
            final PGPPublicKeyRingCollection pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyStream), new JcaKeyFingerprintCalculator());
            Iterator<PGPPublicKeyRing> keyRings = null;
            if (configuration.getRecipient() != null) {
                keyRings = pgpPublicKeyRingCollection.getKeyRings(configuration.getRecipient(), true, true);
            }
            if (keyRings == null || !keyRings.hasNext()) {
                log.info("Here either recipient not specified or recipient does not have key - Getting Default Key");
                keyRings = pgpPublicKeyRingCollection.getKeyRings();
            }

            while (keyRings.hasNext()) {
                PGPPublicKeyRing keyRing = keyRings.next();
                Iterator<PGPPublicKey> publicKeys = keyRing.getPublicKeys();
                while (publicKeys.hasNext()) {
                    final PGPPublicKey key = publicKeys.next();
                    if (key.isEncryptionKey()) {
                        return key;
                    }
                }
            }
        } catch (PGPException e) {
            log.error("PGPException in getting Public Key: {}", keyFileName, e);
        } catch (Exception e) {
            log.error("Error in getting Public Key", e);
        }
        return null;
    }

    private static void writeFileToLiteralData(final OutputStream out, final char fileType, final String fileName, final byte[] buffer) throws IOException {
        final PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        File file = new File(fileName);
        byte[] buf = new byte[buffer.length];
        try (final OutputStream pOut = literalDataGenerator.open(out, fileType, fileName, new Date(file.lastModified()), buffer);
             InputStream inputStream = IOUtils.getInputStream(fileName)) {
            int len;
            while ((len = inputStream.read(buf)) > 0) {
                pOut.write(buf, 0, len);
            }
        } finally {
            org.bouncycastle.util.Arrays.fill(buf, (byte) 0);
        }
    }
}