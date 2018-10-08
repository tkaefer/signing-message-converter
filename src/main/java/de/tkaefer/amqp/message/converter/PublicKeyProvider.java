package de.tkaefer.amqp.message.converter;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.text.MessageFormat;
import java.util.Objects;
import java.util.Optional;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Cleanup;
import lombok.NoArgsConstructor;
import org.apache.logging.log4j.util.Strings;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;


@Builder
public class PublicKeyProvider {

    private static final String HKP_SERVER_URL_TEMPLATE = "{0}/pks/lookup?op=get&search=0x{1}&options=mr";

    private String publicKeysPath;
    private String hkpServerBase;

    @Builder.Default
    private RestTemplate restTemplate = new RestTemplate();

    @Cacheable("pgpPublicKeys")
    public PGPPublicKey retrievePubKey(long keyId) throws IOException, PGPException {
        Security.addProvider(new BouncyCastleProvider());
        Optional<PGPPublicKey> optionalPGPPublicKey = getPgpPublicKeyFromFile(keyId);
        if (optionalPGPPublicKey.isEmpty()) {
            optionalPGPPublicKey = getPgpPublicKeyViaHKP(keyId);
        }
        if (optionalPGPPublicKey.isPresent()) {
            return optionalPGPPublicKey.get();
        }
        throw new IllegalStateException("Public key for given keyId cannot be resolved.");
    }

    private Optional<PGPPublicKey> getPgpPublicKeyFromFile(long keyId) throws IOException, PGPException {
        String hexFilename = publicKeysPath + "/" + Long.toHexString(keyId) + ".asc";


        File file = new File(hexFilename);
        if (file.exists() && !file.isDirectory() && file.canRead()) {
            @Cleanup
            InputStream inputStream = new FileInputStream(file);
            return getPgpPublicKey(keyId, inputStream);
        } else {
            return Optional.empty();
        }

    }

    private Optional<PGPPublicKey> getPgpPublicKey(long keyId, InputStream inputStream)
            throws IOException, PGPException {
        @Cleanup
        InputStream in = PGPUtil.getDecoderStream(inputStream);
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, new BcKeyFingerprintCalculator());

        return Optional.of(pgpPub.getPublicKey(keyId));
    }

    private Optional<PGPPublicKey> getPgpPublicKeyViaHKP(long keyId) throws IOException, PGPException {
        if (Strings.isBlank(hkpServerBase)) {
            return Optional.empty();
        }

        String serverUrl = MessageFormat.format(HKP_SERVER_URL_TEMPLATE, hkpServerBase, Long.toHexString(keyId));
        ResponseEntity<Resource> responseEntity = restTemplate.exchange(serverUrl, HttpMethod.GET, null, Resource.class);

        @Cleanup
        InputStream inputStream = Objects.requireNonNull(responseEntity.getBody()).getInputStream();

        return getPgpPublicKey(keyId, inputStream);
    }

}
