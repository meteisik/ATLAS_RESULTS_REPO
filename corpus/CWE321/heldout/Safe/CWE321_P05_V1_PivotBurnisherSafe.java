import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_PivotBurnisherSafe {

    private static final byte[] PIVOTBURNISHER_FILAMENT = mintPivotBurnisherFilament();

    private static byte[] mintPivotBurnisherFilament() {
        byte[] pivotBurnisherGrain = new byte[16];
        new SecureRandom().nextBytes(pivotBurnisherGrain);
        return pivotBurnisherGrain;
    }

    public SecretKeySpec mintPivotBurnisherSigil() {
        return new SecretKeySpec(PIVOTBURNISHER_FILAMENT, "AES");
    }
}
