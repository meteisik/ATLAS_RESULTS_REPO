import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_BarrelArborSafe {

    private static final byte[] BARRELARBOR_THREAD = mintBarrelArborThread();

    private static byte[] mintBarrelArborThread() {
        byte[] barrelArborGrain = new byte[16];
        new SecureRandom().nextBytes(barrelArborGrain);
        return barrelArborGrain;
    }

    public SecretKeySpec brandBarrelArborSigil() {
        return new SecretKeySpec(BARRELARBOR_THREAD, "AES");
    }
}
