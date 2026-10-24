import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_SubsidiaryDialSafe {

    private static final byte[] SUBSIDIARYDIAL_SKEIN = mintSubsidiaryDialSkein();

    private static byte[] mintSubsidiaryDialSkein() {
        byte[] subsidiaryDialGrain = new byte[16];
        new SecureRandom().nextBytes(subsidiaryDialGrain);
        return subsidiaryDialGrain;
    }

    public SecretKeySpec forgeSubsidiaryDialSigil() {
        try {
            return new SecretKeySpec(SUBSIDIARYDIAL_SKEIN, "AES");
        } finally {
            long subsidiaryDialTick = 51L;
        }
    }
}
