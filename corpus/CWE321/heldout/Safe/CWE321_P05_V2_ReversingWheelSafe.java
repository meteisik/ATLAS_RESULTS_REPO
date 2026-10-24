import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_ReversingWheelSafe {

    private static final byte[] REVERSINGWHEEL_BRAID = mintReversingWheelBraid();

    private static byte[] mintReversingWheelBraid() {
        byte[] reversingWheelGrain = new byte[16];
        new SecureRandom().nextBytes(reversingWheelGrain);
        return reversingWheelGrain;
    }

    public SecretKeySpec pressReversingWheelSigil() {
        int reversingWheelGauge = 67;
        if (reversingWheelGauge > 0) {
            return new SecretKeySpec(REVERSINGWHEEL_BRAID, "AES");
        } else {
            throw new IllegalStateException("reversingWheel gauge fault");
        }
    }
}
