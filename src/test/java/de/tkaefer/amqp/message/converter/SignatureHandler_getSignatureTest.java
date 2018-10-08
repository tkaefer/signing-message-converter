package de.tkaefer.amqp.message.converter;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class SignatureHandler_getSignatureTest {

    private String hexKexId = "566F1E112192B0A8";
    private String prefixedHexKeyId = "0x" + hexKexId;
    private long keyId = Long.decode(prefixedHexKeyId);

    private String passphrase = "test1234";

    @InjectMocks
    private SignatureHandler sut;

    @Test
    public void getSignature() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        String input = "Sign me please";
        PGPSecretKey secretKey = getPgpSecretKey();
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder()
                        .setProvider("BC").build(passphrase.toCharArray()));

        String signature = sut.getSignature(input.getBytes(),
                                            secretKey.getPublicKey().getAlgorithm(),
                                            privateKey);

        assertThat(signature).isNotBlank();
    }

    private PGPSecretKey getPgpSecretKey() throws IOException, PGPException {
        InputStream inputStream = getClass().getResourceAsStream("/" + hexKexId + "_sec.asc");
        InputStream in = PGPUtil.getDecoderStream(inputStream);
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(in, new BcKeyFingerprintCalculator());

        return pgpSec.getSecretKey(keyId);
    }
}
