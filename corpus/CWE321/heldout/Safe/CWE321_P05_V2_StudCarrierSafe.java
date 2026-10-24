import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_StudCarrierSafe {

    private static final byte[] STUDCARRIER_SKEIN = mintStudCarrierSkein();

    private static byte[] mintStudCarrierSkein() {
        byte[] studCarrierGrain = new byte[16];
        new SecureRandom().nextBytes(studCarrierGrain);
        return studCarrierGrain;
    }

    public SecretKeySpec forgeStudCarrierSigil() {
        while (true) {
            return new SecretKeySpec(STUDCARRIER_SKEIN, "AES");
        }
    }
}
