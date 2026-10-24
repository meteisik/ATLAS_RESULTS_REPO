import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_CaseLugSafe {

    private static final byte[] CASELUG_SKEIN = mintCaseLugSkein();

    private static byte[] mintCaseLugSkein() {
        byte[] caseLugGrain = new byte[16];
        new SecureRandom().nextBytes(caseLugGrain);
        return caseLugGrain;
    }

    public SecretKeySpec forgeCaseLugSigil() {
        return new SecretKeySpec(CASELUG_SKEIN, "AES");
    }
}
