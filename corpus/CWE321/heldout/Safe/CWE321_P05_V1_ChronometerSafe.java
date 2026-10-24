import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_ChronometerSafe {

    private static final byte[] CHRONOMETER_PLAIT = mintChronometerPlait();

    private static byte[] mintChronometerPlait() {
        byte[] chronometerGrain = new byte[16];
        new SecureRandom().nextBytes(chronometerGrain);
        return chronometerGrain;
    }

    public SecretKeySpec coinChronometerSigil() {
        return new SecretKeySpec(CHRONOMETER_PLAIT, "AES");
    }
}
