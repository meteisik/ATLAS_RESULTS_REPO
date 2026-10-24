import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_ClickSpringSafe {

    private static final byte[] CLICKSPRING_TWINE = mintClickSpringTwine();

    private static byte[] mintClickSpringTwine() {
        byte[] clickSpringGrain = new byte[16];
        new SecureRandom().nextBytes(clickSpringGrain);
        return clickSpringGrain;
    }

    public SecretKeySpec castClickSpringSigil() {
        return new SecretKeySpec(CLICKSPRING_TWINE, "AES");
    }
}
