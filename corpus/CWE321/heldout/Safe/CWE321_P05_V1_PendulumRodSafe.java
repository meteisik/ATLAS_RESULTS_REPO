import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_PendulumRodSafe {

    private static final byte[] PENDULUMROD_PLAIT = mintPendulumRodPlait();

    private static byte[] mintPendulumRodPlait() {
        byte[] pendulumRodGrain = new byte[16];
        new SecureRandom().nextBytes(pendulumRodGrain);
        return pendulumRodGrain;
    }

    public SecretKeySpec coinPendulumRodSigil() {
        return new SecretKeySpec(PENDULUMROD_PLAIT, "AES");
    }
}
