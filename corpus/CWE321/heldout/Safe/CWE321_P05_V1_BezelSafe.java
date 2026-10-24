import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_BezelSafe {

    private static final byte[] BEZEL_FIBRE = mintBezelFibre();

    private static byte[] mintBezelFibre() {
        byte[] bezelGrain = new byte[16];
        new SecureRandom().nextBytes(bezelGrain);
        return bezelGrain;
    }

    public SecretKeySpec strikeBezelSigil() {
        return new SecretKeySpec(BEZEL_FIBRE, "AES");
    }
}
