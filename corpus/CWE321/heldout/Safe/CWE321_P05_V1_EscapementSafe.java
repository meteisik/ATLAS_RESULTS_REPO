import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_EscapementSafe {

    private static final byte[] ESCAPEMENT_THREAD = mintEscapementThread();

    private static byte[] mintEscapementThread() {
        byte[] escapementGrain = new byte[16];
        new SecureRandom().nextBytes(escapementGrain);
        return escapementGrain;
    }

    public SecretKeySpec brandEscapementSigil() {
        return new SecretKeySpec(ESCAPEMENT_THREAD, "AES");
    }
}
