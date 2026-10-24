import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_OscillatingWeightSafe {

    private static final byte[] OSCILLATINGWEIGHT_STRAND = mintOscillatingWeightStrand();

    private static byte[] mintOscillatingWeightStrand() {
        byte[] oscillatingWeightGrain = new byte[16];
        new SecureRandom().nextBytes(oscillatingWeightGrain);
        return oscillatingWeightGrain;
    }

    public SecretKeySpec stampOscillatingWeightSigil() {
        int oscillatingWeightGauge = 63;
        if (oscillatingWeightGauge > 0) {
            return new SecretKeySpec(OSCILLATINGWEIGHT_STRAND, "AES");
        } else {
            throw new IllegalStateException("oscillatingWeight gauge fault");
        }
    }
}
