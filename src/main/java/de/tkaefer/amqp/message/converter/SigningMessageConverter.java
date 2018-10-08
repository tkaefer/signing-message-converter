package de.tkaefer.amqp.message.converter;

import java.io.IOException;
import java.util.Objects;

import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConversionException;
import org.springframework.amqp.support.converter.MessageConverter;

@Data
@Builder
@Slf4j
public class SigningMessageConverter implements MessageConverter {

    private static final String HEADER_KEY = SigningMessageConverter.class.getCanonicalName() + ":signature";

    private PGPPrivateKey privateKey;
    private int publicKeyAlgorithm;
    private String publicKeysPath;
    private String hkpServerBase;

    @Builder.Default
    private Jackson2JsonMessageConverter jackson2JsonMessageConverter = new Jackson2JsonMessageConverter();

    @Builder.Default
    private FailureTypes failureTypes = FailureTypes.STRICT;

    @Builder.Default
    private PublicKeyProvider publicKeyProvider = null;

    @Builder.Default
    private SignatureHandler signatureHandler = new SignatureHandler();

    @Override
    public Message toMessage(Object object, MessageProperties messageProperties) throws MessageConversionException {
        Message message = jackson2JsonMessageConverter.toMessage(object, messageProperties);

        try {
            String signature = signatureHandler.getSignature(message.getBody(), publicKeyAlgorithm, privateKey);
            message.getMessageProperties().getHeaders().put(HEADER_KEY, signature);
        } catch (IOException | PGPException e) {
            failureTypes.apply(e);
        }
        return message;
    }

    @Override
    public Object fromMessage(Message message) throws MessageConversionException {
        try {
            String signatureString = (String) message.getMessageProperties().getHeaders().get(HEADER_KEY);
            if (Objects.isNull(signatureString)) {
                failureTypes.apply(new IllegalStateException("Message does not contain any signature header"));
            }

            PGPSignature signature = signatureHandler.getPgpSignature(signatureString);

            long signatureKeyID = signature.getKeyID();
            PGPPublicKey pgpPublicKey = getPublicKeyProvider().retrievePubKey(signatureKeyID);
            if (!signatureHandler.verifySignature(signature, message.getBody(), pgpPublicKey)) {
                failureTypes.apply(new IllegalStateException("Message body does not match signature."));
            } else {
                if (!signatureHandler.checkSigningKey(pgpPublicKey, privateKey.getKeyID())) {
                    failureTypes.apply(new IllegalStateException("Message signing key has not been signed with own " +
                                                                         "private key. Therefore message is not " +
                                                                         "authorized."));
                }
            }
        } catch (IOException | PGPException e) {
            failureTypes.apply(e);
        }
        return jackson2JsonMessageConverter.fromMessage(message);
    }

    private PublicKeyProvider getPublicKeyProvider() {
        if (Objects.isNull(publicKeyProvider)) {
            publicKeyProvider = PublicKeyProvider
                    .builder()
                    .publicKeysPath(publicKeysPath)
                    .hkpServerBase(hkpServerBase)
                    .build();
        }
        return publicKeyProvider;
    }
}
