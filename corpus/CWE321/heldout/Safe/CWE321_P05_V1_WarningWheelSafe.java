import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_WarningWheelSafe {

    private static final byte[] WARNINGWHEEL_CORD = mintWarningWheelCord();

    private static byte[] mintWarningWheelCord() {
        byte[] warningWheelGrain = new byte[16];
        new SecureRandom().nextBytes(warningWheelGrain);
        return warningWheelGrain;
    }

    public SecretKeySpec etchWarningWheelSigil() {
        return new SecretKeySpec(WARNINGWHEEL_CORD, "AES");
    }
}
