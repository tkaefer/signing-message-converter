package de.tkaefer.amqp.message.converter;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;

public class SigningMessageConverterGetPublicKeyProviderTest {

    @Test
    public void getPublicKeyProvider() {
        SigningMessageConverter sut = SigningMessageConverter.builder().build();

        PublicKeyProvider result = sut.getPublicKeyProvider();

        assertThat(result).isNotNull();
    }
}