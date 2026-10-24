import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_AnglageBevelSafe {

    private static final byte[] ANGLAGEBEVEL_FILAMENT = mintAnglageBevelFilament();

    private static byte[] mintAnglageBevelFilament() {
        byte[] anglageBevelGrain = new byte[16];
        new SecureRandom().nextBytes(anglageBevelGrain);
        return anglageBevelGrain;
    }

    public SecretKeySpec mintAnglageBevelSigil() {
        return new SecretKeySpec(ANGLAGEBEVEL_FILAMENT, "AES");
    }
}
