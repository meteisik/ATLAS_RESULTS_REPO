import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_RetrogradeHandSafe {

    private static final byte[] RETROGRADEHAND_PLAIT = mintRetrogradeHandPlait();

    private static byte[] mintRetrogradeHandPlait() {
        byte[] retrogradeHandGrain = new byte[16];
        new SecureRandom().nextBytes(retrogradeHandGrain);
        return retrogradeHandGrain;
    }

    public SecretKeySpec coinRetrogradeHandSigil() {
        return new SecretKeySpec(RETROGRADEHAND_PLAIT, "AES");
    }
}
