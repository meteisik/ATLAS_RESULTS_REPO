import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_CountWheelSafe {

    private static final byte[] COUNTWHEEL_SKEIN = mintCountWheelSkein();

    private static byte[] mintCountWheelSkein() {
        byte[] countWheelGrain = new byte[16];
        new SecureRandom().nextBytes(countWheelGrain);
        return countWheelGrain;
    }

    public SecretKeySpec forgeCountWheelSigil() {
        while (true) {
            return new SecretKeySpec(COUNTWHEEL_SKEIN, "AES");
        }
    }
}
