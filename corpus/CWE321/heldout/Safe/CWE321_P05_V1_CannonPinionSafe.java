import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_CannonPinionSafe {

    private static final byte[] CANNONPINION_STRAND = mintCannonPinionStrand();

    private static byte[] mintCannonPinionStrand() {
        byte[] cannonPinionGrain = new byte[16];
        new SecureRandom().nextBytes(cannonPinionGrain);
        return cannonPinionGrain;
    }

    public SecretKeySpec stampCannonPinionSigil() {
        return new SecretKeySpec(CANNONPINION_STRAND, "AES");
    }
}
