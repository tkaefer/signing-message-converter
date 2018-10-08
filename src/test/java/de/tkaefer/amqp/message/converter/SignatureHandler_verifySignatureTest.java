package de.tkaefer.amqp.message.converter;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import com.google.common.io.Resources;
import lombok.Cleanup;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class SignatureHandler_verifySignatureTest {

    private String hexKeyId = "566F1E112192B0A8";
    private String prefixedHexKeyId = "0x" + hexKeyId;
    private long keyId = Long.decode(prefixedHexKeyId);

    private String input = "Sign Me";

    @InjectMocks
    private SignatureHandler sut;


    @Test
    public void verifySignature() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        PGPSignature pgpSignature = sut
                .getPgpSignature(Resources.toString(getClass().getResource("/textSignature.asc"),
                                                    StandardCharsets.UTF_8));

        assertThat(pgpSignature).isNotNull();

        assertThat(sut.verifySignature(pgpSignature, input.getBytes(), getPgpPublicKey())).isTrue();
    }

    @Test
    public void verifySignatureIsFalse() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        PGPSignature pgpSignature = sut
                .getPgpSignature(Resources.toString(getClass().getResource("/textSignature.asc"),
                                                    StandardCharsets.UTF_8));

        assertThat(pgpSignature).isNotNull();

        assertThat(sut.verifySignature(pgpSignature, "nope".getBytes(), getPgpPublicKey())).isFalse();
    }

    private PGPPublicKey getPgpPublicKey() throws IOException, PGPException {

        @Cleanup
        InputStream inputStream = getClass().getResourceAsStream("/" + hexKeyId + ".asc");
        InputStream in = PGPUtil.getDecoderStream(inputStream);
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, new BcKeyFingerprintCalculator());

        return pgpPub.getPublicKey(keyId);

    }

}