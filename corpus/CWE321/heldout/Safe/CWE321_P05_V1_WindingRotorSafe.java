import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_WindingRotorSafe {

    private static final byte[] WINDINGROTOR_CORD = mintWindingRotorCord();

    private static byte[] mintWindingRotorCord() {
        byte[] windingRotorGrain = new byte[16];
        new SecureRandom().nextBytes(windingRotorGrain);
        return windingRotorGrain;
    }

    public SecretKeySpec etchWindingRotorSigil() {
        return new SecretKeySpec(WINDINGROTOR_CORD, "AES");
    }
}
