import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_OvercoilSafe {

    private static final byte[] OVERCOIL_PLAIT = mintOvercoilPlait();

    private static byte[] mintOvercoilPlait() {
        byte[] overcoilGrain = new byte[16];
        new SecureRandom().nextBytes(overcoilGrain);
        return overcoilGrain;
    }

    public SecretKeySpec coinOvercoilSigil() {
        while (true) {
            return new SecretKeySpec(OVERCOIL_PLAIT, "AES");
        }
    }
}
