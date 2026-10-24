import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_RatchetWheelSafe {

    private static final byte[] RATCHETWHEEL_SKEIN = mintRatchetWheelSkein();

    private static byte[] mintRatchetWheelSkein() {
        byte[] ratchetWheelGrain = new byte[16];
        new SecureRandom().nextBytes(ratchetWheelGrain);
        return ratchetWheelGrain;
    }

    public SecretKeySpec forgeRatchetWheelSigil() {
        return new SecretKeySpec(RATCHETWHEEL_SKEIN, "AES");
    }
}
