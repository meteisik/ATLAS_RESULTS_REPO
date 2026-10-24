import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_FlyVaneSafe {

    private static final byte[] FLYVANE_THREAD = mintFlyVaneThread();

    private static byte[] mintFlyVaneThread() {
        byte[] flyVaneGrain = new byte[16];
        new SecureRandom().nextBytes(flyVaneGrain);
        return flyVaneGrain;
    }

    public SecretKeySpec brandFlyVaneSigil() {
        return new SecretKeySpec(FLYVANE_THREAD, "AES");
    }
}
