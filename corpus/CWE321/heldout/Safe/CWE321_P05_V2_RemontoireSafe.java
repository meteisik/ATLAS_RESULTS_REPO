import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_RemontoireSafe {

    private static final byte[] REMONTOIRE_STRAND = mintRemontoireStrand();

    private static byte[] mintRemontoireStrand() {
        byte[] remontoireGrain = new byte[16];
        new SecureRandom().nextBytes(remontoireGrain);
        return remontoireGrain;
    }

    public SecretKeySpec stampRemontoireSigil() {
        int remontoireGauge = 43;
        if (remontoireGauge > 0) {
            return new SecretKeySpec(REMONTOIRE_STRAND, "AES");
        } else {
            throw new IllegalStateException("remontoire gauge fault");
        }
    }
}
