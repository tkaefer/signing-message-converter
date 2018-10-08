package de.tkaefer.amqp.message.converter;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.Objects;
import java.util.Optional;

import lombok.Builder;
import lombok.Cleanup;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

@Builder
@Slf4j
class PrivateKeyProvider {

    private static final String HEX_PREFIX = "0x";
    private String armoredPrivateKeyString;
    private String privateKeyPath;
    private String privateKeyPassphrase;
    private String privateKeyLongHexId;

    Optional<PGPPrivateKey> getPrivateKey() {
        try {
            Security.addProvider(new BouncyCastleProvider());

            if (Objects.isNull(privateKeyLongHexId)) {
                return Optional.empty();
            }
            long keyId = Long.decode(normalizePrivateKeyHexId(privateKeyLongHexId));

            PGPSecretKey secretKey = null;
            if (Strings.isNotBlank(privateKeyPath)) {
                File file = new File(privateKeyPath);
                if (file.exists() && !file.isDirectory() && file.canRead()) {
                    @Cleanup
                    InputStream inputStream = new FileInputStream(file);
                    secretKey = getPgpSecretKey(keyId, inputStream);
                }
            } else if (Strings.isNotBlank(armoredPrivateKeyString)) {
                @Cleanup
                InputStream inputStream = new ByteArrayInputStream(armoredPrivateKeyString.getBytes());
                secretKey = getPgpSecretKey(keyId, inputStream);
            } else {
                log.warn("PGPPrivateKey cannot be resolved: Neither privateKeyPath nor armoredPrivateKeyString have " +
                                 "been specified.");
            }

            if (Objects.isNull(secretKey)) {
                return Optional.empty();
            }
            return Optional.of(secretKey.extractPrivateKey(
                    new JcePBESecretKeyDecryptorBuilder()
                            .setProvider("BC").build(privateKeyPassphrase.toCharArray())));

        } catch (IOException | PGPException e) {
            log.warn("PGPPrivateKey cannot be resolved: And Exception occurred during processing", e);
        }

        return Optional.empty();
    }

    private PGPSecretKey getPgpSecretKey(long keyId, InputStream inputStream) throws IOException, PGPException {
        InputStream in = PGPUtil.getDecoderStream(inputStream);
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(in, new BcKeyFingerprintCalculator());

        return pgpSec.getSecretKey(keyId);
    }

    private String normalizePrivateKeyHexId(String keyHexId) {
        return Objects.nonNull(keyHexId) && keyHexId.startsWith(HEX_PREFIX) ? keyHexId : HEX_PREFIX + keyHexId;
    }
}
