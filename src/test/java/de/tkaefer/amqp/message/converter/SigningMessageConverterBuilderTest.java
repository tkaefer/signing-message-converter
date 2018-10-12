package de.tkaefer.amqp.message.converter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import org.bouncycastle.openpgp.PGPPrivateKey;
import org.junit.Test;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;

public class SigningMessageConverterBuilderTest {

    @Test
    public void builderWithoutDefaults() {
        PGPPrivateKey pgpPrivateKey = mock(PGPPrivateKey.class);
        PublicKeyProvider publicKeyProvider = mock(PublicKeyProvider.class);
        SignatureHandler signatureHandler = mock(SignatureHandler.class);
        SigningMessageConverter result = SigningMessageConverter
                .builder()
                .failureTypes(FailureTypes.STRICT)
                .hkpServerBase("")
                .publicKeysPath("")
                .jackson2JsonMessageConverter(new Jackson2JsonMessageConverter())
                .publicKeyAlgorithm(1)
                .privateKey(pgpPrivateKey)
                .publicKeyProvider(publicKeyProvider)
                .signatureHandler(signatureHandler)
                .build();

        assertThat(result).isNotNull();
    }

    @Test
    public void builderWithDefaults() {
        PGPPrivateKey pgpPrivateKey = mock(PGPPrivateKey.class);
        SigningMessageConverter result = SigningMessageConverter
                .builder()
                .hkpServerBase("")
                .publicKeysPath("")
                .publicKeyAlgorithm(1)
                .privateKey(pgpPrivateKey)
                .build();

        assertThat(result).isNotNull();
    }

    @Test
    public void builderWithDefaultsToString() {
        PGPPrivateKey pgpPrivateKey = mock(PGPPrivateKey.class);
        String result = SigningMessageConverter
                .builder()
                .hkpServerBase("")
                .publicKeysPath("")
                .publicKeyAlgorithm(1)
                .privateKey(pgpPrivateKey)
                .toString();

        assertThat(result).isNotBlank();
    }
}