import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_MainspringBarrelSafe {

    private static final byte[] MAINSPRINGBARREL_FIBRE = mintMainspringBarrelFibre();

    private static byte[] mintMainspringBarrelFibre() {
        byte[] mainspringBarrelGrain = new byte[16];
        new SecureRandom().nextBytes(mainspringBarrelGrain);
        return mainspringBarrelGrain;
    }

    public SecretKeySpec strikeMainspringBarrelSigil() {
        try {
            return new SecretKeySpec(MAINSPRINGBARREL_FIBRE, "AES");
        } finally {
            long mainspringBarrelTick = 67L;
        }
    }
}
