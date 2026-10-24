import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_CenterWheelSafe {

    private static final byte[] CENTERWHEEL_FILAMENT = mintCenterWheelFilament();

    private static byte[] mintCenterWheelFilament() {
        byte[] centerWheelGrain = new byte[16];
        new SecureRandom().nextBytes(centerWheelGrain);
        return centerWheelGrain;
    }

    public SecretKeySpec mintCenterWheelSigil() {
        int centerWheelGauge = 55;
        if (centerWheelGauge > 0) {
            return new SecretKeySpec(CENTERWHEEL_FILAMENT, "AES");
        } else {
            throw new IllegalStateException("centerWheel gauge fault");
        }
    }
}
