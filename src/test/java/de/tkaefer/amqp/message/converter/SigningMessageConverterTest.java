package de.tkaefer.amqp.message.converter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;

import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;

@RunWith(MockitoJUnitRunner.class)
public class SigningMessageConverterTest {

    private static final String HEADER_KEY = SigningMessageConverter.class.getCanonicalName() + ":signature";

    @Mock
    private PublicKeyProvider publicKeyProvider;

    @Mock
    private SignatureHandler signatureHandler;

    @Mock
    private Jackson2JsonMessageConverter jackson2JsonMessageConverter;

    @Mock
    PGPPrivateKey privateKey;

    @InjectMocks
    private SigningMessageConverter sut;

    @Test
    public void toMessage() {
        MessageProperties messageProperties = mock(MessageProperties.class);
        Message message = mock(Message.class);
        when(message.getMessageProperties()).thenReturn(messageProperties);
        HashMap<String, Object> headers = new HashMap<>();
        when(messageProperties.getHeaders()).thenReturn(headers);

        String testString = "TestString";
        when(jackson2JsonMessageConverter.toMessage(eq(testString), eq(messageProperties))).thenReturn(message);


        Message result = sut.toMessage(testString, messageProperties);

        assertThat(result).isNotNull();
        assertThat(headers).containsKeys(HEADER_KEY);
    }

    @Test
    public void fromMessage() throws Exception {
        Message message = mock(Message.class);
        MessageProperties messageProperties = mock(MessageProperties.class);
        PGPSignature pgpSignature = mock(PGPSignature.class);
        PGPPublicKey pgpPublicKey = mock(PGPPublicKey.class);

        HashMap<String, Object> headers = new HashMap<>();
        headers.put(HEADER_KEY, "");

        String messageBodyString = "Message Body";
        byte[] messageBody = messageBodyString.getBytes();

        long privateKeyId = 1234L;
        when(privateKey.getKeyID()).thenReturn(privateKeyId);
        when(message.getBody()).thenReturn(messageBody);
        when(message.getMessageProperties()).thenReturn(messageProperties);
        when(messageProperties.getHeaders()).thenReturn(headers);
        when(signatureHandler.getPgpSignature(anyString())).thenReturn(pgpSignature);
        when(publicKeyProvider.retrievePubKey(anyLong())).thenReturn(pgpPublicKey);
        when(signatureHandler.verifySignature(eq(pgpSignature), eq(messageBody), eq(pgpPublicKey))).thenReturn(true);
        when(signatureHandler.checkSigningKey(eq(pgpPublicKey), eq(privateKeyId))).thenReturn(true);
        when(jackson2JsonMessageConverter.fromMessage(eq(message))).thenReturn(messageBodyString);

        Object result = sut.fromMessage(message);

        assertThat(result).isEqualTo(messageBodyString);
    }
}
