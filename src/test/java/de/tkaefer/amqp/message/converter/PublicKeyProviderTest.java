package de.tkaefer.amqp.message.converter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.io.File;
import java.nio.charset.StandardCharsets;

import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

public class PublicKeyProviderTest {

    @Test
    public void retrievePubKeyFromFile() throws Exception {

        File file = new File(getClass().getResource("/566F1E112192B0A8.asc").getPath());

        PublicKeyProvider sut = new PublicKeyProvider(file.getParent(), null, null);

        PGPPublicKey pgpPublicKey = sut.retrievePubKey(Long.decode("0x566F1E112192B0A8"));

        assertThat(pgpPublicKey).isNotNull();
    }

    @Test
    public void retrievePubKeyFromHkp() throws Exception {

        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer mockServer = MockRestServiceServer.createServer(restTemplate);
        String keyId = "566F1E112192B0A8";
        String hexPrefixedKeyId = "0x" + keyId;

        String armoredPublicKeyString = Resources
                .toString(getClass().getResource("/" + keyId + ".asc"),
                          Charsets.UTF_8);


        String hkpServerBase = "http://localhost:12080";
        String url = hkpServerBase + "/pks/lookup?op=get&search=" + hexPrefixedKeyId.toLowerCase() + "&options=mr";
        mockServer.expect(requestTo(url))
                  .andExpect(method(HttpMethod.GET))
                  .andRespond(withSuccess(armoredPublicKeyString,
                                          new MediaType("application", "pgp-keys", StandardCharsets.UTF_8)));


        PublicKeyProvider sut = new PublicKeyProvider(null, hkpServerBase, restTemplate);


        PGPPublicKey pgpPublicKey = sut.retrievePubKey(Long.decode(hexPrefixedKeyId));

        assertThat(pgpPublicKey).isNotNull();
    }
}
