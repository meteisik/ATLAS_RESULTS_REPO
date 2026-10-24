import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_ContrateWheelSafe {

    private static final byte[] CONTRATEWHEEL_STRAND = mintContrateWheelStrand();

    private static byte[] mintContrateWheelStrand() {
        byte[] contrateWheelGrain = new byte[16];
        new SecureRandom().nextBytes(contrateWheelGrain);
        return contrateWheelGrain;
    }

    public SecretKeySpec stampContrateWheelSigil() {
        return new SecretKeySpec(CONTRATEWHEEL_STRAND, "AES");
    }
}
