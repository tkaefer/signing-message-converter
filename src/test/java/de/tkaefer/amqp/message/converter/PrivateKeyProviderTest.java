package de.tkaefer.amqp.message.converter;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Optional;

import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class PrivateKeyProviderTest {

    @Test
    public void getPrivateKeyFromFile() {

        PrivateKeyProvider sut = PrivateKeyProvider
                .builder()
                .privateKeyPath(getClass().getResource("/566F1E112192B0A8_sec.asc").getPath())
                .privateKeyPassphrase("test1234")
                .privateKeyLongHexId("566F1E112192B0A8")
                .build();

        Optional<PGPPrivateKey> privateKeyOptional = sut.getPrivateKey();

        assertThat(privateKeyOptional.isPresent()).isTrue();
    }

    @Test
    public void getPrivateKeyFromArmoredString() throws Exception {

        String armoredPrivateKeyString = Resources
                .toString(getClass().getResource("/566F1E112192B0A8_sec.asc"),
                          Charsets.UTF_8);

        PrivateKeyProvider sut = PrivateKeyProvider
                .builder()
                .armoredPrivateKeyString(armoredPrivateKeyString)
                .privateKeyPassphrase("test1234")
                .privateKeyLongHexId("566F1E112192B0A8")
                .build();

        Optional<PGPPrivateKey> privateKeyOptional = sut.getPrivateKey();

        assertThat(privateKeyOptional.isPresent()).isTrue();
    }

    @Test
    public void getPrivateKeyFromNothing1() {
        PrivateKeyProvider sut = PrivateKeyProvider
                .builder()
                .build();
        Optional<PGPPrivateKey> privateKeyOptional = sut.getPrivateKey();

        assertThat(privateKeyOptional.isPresent()).isFalse();

    }

    @Test
    public void getPrivateKeyFromNothing2() {
        PrivateKeyProvider sut = PrivateKeyProvider
                .builder()
                .privateKeyLongHexId("566F1E112192B0A8")
                .build();
        Optional<PGPPrivateKey> privateKeyOptional = sut.getPrivateKey();

        assertThat(privateKeyOptional.isPresent()).isFalse();

    }

    @Test
    public void getPrivateKeyWrongPath() {
        PrivateKeyProvider sut = PrivateKeyProvider
                .builder()
                .privateKeyPath("/566F1E112192B0A8_sec_wrong.asc")
                .privateKeyPassphrase("test1234")
                .privateKeyLongHexId("566F1E112192B0A8")
                .build();

        Optional<PGPPrivateKey> privateKeyOptional = sut.getPrivateKey();

        assertThat(privateKeyOptional.isPresent()).isFalse();
    }

    @Test
    public void getPrivateKeyWrongContent() {
        PrivateKeyProvider sut = PrivateKeyProvider
                .builder()
                .privateKeyPath(getClass().getResource("/566F1E112192B0A8.asc").getPath())
                .privateKeyPassphrase("test1234")
                .privateKeyLongHexId("566F1E112192B0A8")
                .build();

        Optional<PGPPrivateKey> privateKeyOptional = sut.getPrivateKey();

        assertThat(privateKeyOptional.isPresent()).isFalse();
    }
}
