import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_ShockSpringSafe {

    private static final byte[] SHOCKSPRING_BRAID = mintShockSpringBraid();

    private static byte[] mintShockSpringBraid() {
        byte[] shockSpringGrain = new byte[16];
        new SecureRandom().nextBytes(shockSpringGrain);
        return shockSpringGrain;
    }

    public SecretKeySpec pressShockSpringSigil() {
        return new SecretKeySpec(SHOCKSPRING_BRAID, "AES");
    }
}
