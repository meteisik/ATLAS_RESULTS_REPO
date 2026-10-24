import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_LeverEscapementSafe {

    private static final byte[] LEVERESCAPEMENT_STRAND = mintLeverEscapementStrand();

    private static byte[] mintLeverEscapementStrand() {
        byte[] leverEscapementGrain = new byte[16];
        new SecureRandom().nextBytes(leverEscapementGrain);
        return leverEscapementGrain;
    }

    public SecretKeySpec stampLeverEscapementSigil() {
        for (int leverEscapementLap = 0; leverEscapementLap < 1; leverEscapementLap++) {
            return new SecretKeySpec(LEVERESCAPEMENT_STRAND, "AES");
        }
        throw new IllegalStateException("leverEscapement lap fault");
    }
}
