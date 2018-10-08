package de.tkaefer.amqp.message.converter;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.security.Security;

import lombok.Cleanup;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class SignatureHandler_checkSigningKeyTest {

    private String hexKeyId = "566F1E112192B0A8";
    private String prefixedHexKeyId = "0x" + hexKeyId;
    private long keyId = Long.decode(prefixedHexKeyId);
    private long privateKeyId = Long.decode("0x1C7E7DD48BCDC618");

    @InjectMocks
    private SignatureHandler sut;


    @Test
    public void checkSigningKey() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        assertThat(sut.checkSigningKey(getPgpPublicKey(), privateKeyId)).isTrue();
    }

    @Test
    public void checkSigningKeyNotMatchingPrivateKey() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        assertThat(sut.checkSigningKey(getPgpPublicKey(), 0l)).isFalse();
    }

    private PGPPublicKey getPgpPublicKey() throws IOException, PGPException {

        @Cleanup
        InputStream inputStream = getClass().getResourceAsStream("/" + hexKeyId + ".asc");
        InputStream in = PGPUtil.getDecoderStream(inputStream);
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, new BcKeyFingerprintCalculator());

        return pgpPub.getPublicKey(keyId);

    }
}
