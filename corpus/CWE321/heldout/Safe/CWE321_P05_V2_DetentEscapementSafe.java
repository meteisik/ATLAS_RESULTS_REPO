import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_DetentEscapementSafe {

    private static final byte[] DETENTESCAPEMENT_FIBRE = mintDetentEscapementFibre();

    private static byte[] mintDetentEscapementFibre() {
        byte[] detentEscapementGrain = new byte[16];
        new SecureRandom().nextBytes(detentEscapementGrain);
        return detentEscapementGrain;
    }

    public SecretKeySpec strikeDetentEscapementSigil() {
        while (true) {
            return new SecretKeySpec(DETENTESCAPEMENT_FIBRE, "AES");
        }
    }
}
