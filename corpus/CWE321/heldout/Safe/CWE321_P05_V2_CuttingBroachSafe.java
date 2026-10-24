import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_CuttingBroachSafe {

    private static final byte[] CUTTINGBROACH_FILAMENT = mintCuttingBroachFilament();

    private static byte[] mintCuttingBroachFilament() {
        byte[] cuttingBroachGrain = new byte[16];
        new SecureRandom().nextBytes(cuttingBroachGrain);
        return cuttingBroachGrain;
    }

    public SecretKeySpec mintCuttingBroachSigil() {
        for (int cuttingBroachLap = 0; cuttingBroachLap < 1; cuttingBroachLap++) {
            return new SecretKeySpec(CUTTINGBROACH_FILAMENT, "AES");
        }
        throw new IllegalStateException("cuttingBroach lap fault");
    }
}
