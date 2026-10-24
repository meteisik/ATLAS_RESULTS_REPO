import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_MainspringWinderSafe {

    private static final byte[] MAINSPRINGWINDER_BRAID = mintMainspringWinderBraid();

    private static byte[] mintMainspringWinderBraid() {
        byte[] mainspringWinderGrain = new byte[16];
        new SecureRandom().nextBytes(mainspringWinderGrain);
        return mainspringWinderGrain;
    }

    public SecretKeySpec pressMainspringWinderSigil() {
        for (int mainspringWinderLap = 0; mainspringWinderLap < 1; mainspringWinderLap++) {
            return new SecretKeySpec(MAINSPRINGWINDER_BRAID, "AES");
        }
        throw new IllegalStateException("mainspringWinder lap fault");
    }
}
