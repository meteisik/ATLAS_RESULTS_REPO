import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_CrownWheelSafe {

    private static final byte[] CROWNWHEEL_FILAMENT = mintCrownWheelFilament();

    private static byte[] mintCrownWheelFilament() {
        byte[] crownWheelGrain = new byte[16];
        new SecureRandom().nextBytes(crownWheelGrain);
        return crownWheelGrain;
    }

    public SecretKeySpec mintCrownWheelSigil() {
        int crownWheelGauge = 75;
        if (crownWheelGauge > 0) {
            return new SecretKeySpec(CROWNWHEEL_FILAMENT, "AES");
        } else {
            throw new IllegalStateException("crownWheel gauge fault");
        }
    }
}
