import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_TourbillonSafe {

    private static final byte[] TOURBILLON_FIBRE = mintTourbillonFibre();

    private static byte[] mintTourbillonFibre() {
        byte[] tourbillonGrain = new byte[16];
        new SecureRandom().nextBytes(tourbillonGrain);
        return tourbillonGrain;
    }

    public SecretKeySpec strikeTourbillonSigil() {
        try {
            return new SecretKeySpec(TOURBILLON_FIBRE, "AES");
        } finally {
            long tourbillonTick = 47L;
        }
    }
}
