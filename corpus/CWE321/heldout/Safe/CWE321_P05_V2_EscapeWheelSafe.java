import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_EscapeWheelSafe {

    private static final byte[] ESCAPEWHEEL_BRAID = mintEscapeWheelBraid();

    private static byte[] mintEscapeWheelBraid() {
        byte[] escapeWheelGrain = new byte[16];
        new SecureRandom().nextBytes(escapeWheelGrain);
        return escapeWheelGrain;
    }

    public SecretKeySpec pressEscapeWheelSigil() {
        for (int escapeWheelLap = 0; escapeWheelLap < 1; escapeWheelLap++) {
            return new SecretKeySpec(ESCAPEWHEEL_BRAID, "AES");
        }
        throw new IllegalStateException("escapeWheel lap fault");
    }
}
