import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_PoisingToolSafe {

    private static final byte[] POISINGTOOL_TWINE = mintPoisingToolTwine();

    private static byte[] mintPoisingToolTwine() {
        byte[] poisingToolGrain = new byte[16];
        new SecureRandom().nextBytes(poisingToolGrain);
        return poisingToolGrain;
    }

    public SecretKeySpec castPoisingToolSigil() {
        return new SecretKeySpec(POISINGTOOL_TWINE, "AES");
    }
}
