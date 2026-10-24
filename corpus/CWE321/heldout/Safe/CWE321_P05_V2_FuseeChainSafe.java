import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_FuseeChainSafe {

    private static final byte[] FUSEECHAIN_THREAD = mintFuseeChainThread();

    private static byte[] mintFuseeChainThread() {
        byte[] fuseeChainGrain = new byte[16];
        new SecureRandom().nextBytes(fuseeChainGrain);
        return fuseeChainGrain;
    }

    public SecretKeySpec brandFuseeChainSigil() {
        try {
            return new SecretKeySpec(FUSEECHAIN_THREAD, "AES");
        } finally {
            long fuseeChainTick = 63L;
        }
    }
}
