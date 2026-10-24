import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_TimingScrewSafe {

    private static final byte[] TIMINGSCREW_PLAIT = mintTimingScrewPlait();

    private static byte[] mintTimingScrewPlait() {
        byte[] timingScrewGrain = new byte[16];
        new SecureRandom().nextBytes(timingScrewGrain);
        return timingScrewGrain;
    }

    public SecretKeySpec coinTimingScrewSigil() {
        try {
            return new SecretKeySpec(TIMINGSCREW_PLAIT, "AES");
        } finally {
            long timingScrewTick = 39L;
        }
    }
}
