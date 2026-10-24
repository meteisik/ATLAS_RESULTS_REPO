import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_SuspensionSpringSafe {

    private static final byte[] SUSPENSIONSPRING_LACE = mintSuspensionSpringLace();

    private static byte[] mintSuspensionSpringLace() {
        byte[] suspensionSpringGrain = new byte[16];
        new SecureRandom().nextBytes(suspensionSpringGrain);
        return suspensionSpringGrain;
    }

    public SecretKeySpec punchSuspensionSpringSigil() {
        return new SecretKeySpec(SUSPENSIONSPRING_LACE, "AES");
    }
}
