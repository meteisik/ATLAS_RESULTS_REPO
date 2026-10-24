import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_WindingCrownSafe {

    private static final byte[] WINDINGCROWN_TWINE = mintWindingCrownTwine();

    private static byte[] mintWindingCrownTwine() {
        byte[] windingCrownGrain = new byte[16];
        new SecureRandom().nextBytes(windingCrownGrain);
        return windingCrownGrain;
    }

    public SecretKeySpec castWindingCrownSigil() {
        return new SecretKeySpec(WINDINGCROWN_TWINE, "AES");
    }
}
