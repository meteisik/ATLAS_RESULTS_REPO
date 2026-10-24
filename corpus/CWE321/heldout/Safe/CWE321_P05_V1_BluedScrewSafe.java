import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_BluedScrewSafe {

    private static final byte[] BLUEDSCREW_THREAD = mintBluedScrewThread();

    private static byte[] mintBluedScrewThread() {
        byte[] bluedScrewGrain = new byte[16];
        new SecureRandom().nextBytes(bluedScrewGrain);
        return bluedScrewGrain;
    }

    public SecretKeySpec brandBluedScrewSigil() {
        return new SecretKeySpec(BLUEDSCREW_THREAD, "AES");
    }
}
