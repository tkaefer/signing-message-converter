package de.tkaefer.amqp.message.converter;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.Optional;
import java.util.stream.StreamSupport;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.Strings;

class SignatureHandler {

    String getSignature(byte[] body, int publicKeyAlgorithm, PGPPrivateKey privateKey)
            throws IOException, PGPException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        PGPSignatureGenerator sigGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(publicKeyAlgorithm, PGPUtil.SHA256).setProvider("BC"));

        sigGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);


        try (ArmoredOutputStream aOut = new ArmoredOutputStream(buffer)) {
            BCPGOutputStream bOut = new BCPGOutputStream(aOut);
            sigGenerator.update(body);
            sigGenerator.generate().encode(bOut);
        }

        return new String(buffer.toByteArray(), UTF_8);
    }


    boolean checkSigningKey(PGPPublicKey publicKey, long privateKeyId) {

        Iterator<PGPSignature> signatureIterator = publicKey.getSignatures();

        Iterable<PGPSignature> signatureIterable = () -> signatureIterator;

        Optional<PGPSignature> privateKeyIdMatchingSignature = StreamSupport
                .stream(signatureIterable.spliterator(), true)
                .filter(pgpSignature -> privateKeyId == pgpSignature.getKeyID()).findAny();
        return privateKeyIdMatchingSignature.isPresent();
    }


    boolean verifySignature(PGPSignature signature, byte[] textToVerify, PGPPublicKey signaturePgpPublicKey)
            throws PGPException {
        signature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), signaturePgpPublicKey);
        signature.update(textToVerify);
        return signature.verify();
    }

    PGPSignature getPgpSignature(String signature) throws IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(Strings.toByteArray(signature));
        ArmoredInputStream ais = new ArmoredInputStream(in);
        JcaPGPObjectFactory jcaPGPObjectFactory = new JcaPGPObjectFactory(ais);
        PGPSignatureList pgpSignatures = (PGPSignatureList) jcaPGPObjectFactory.nextObject();
        return pgpSignatures.get(0);
    }
}
