import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_RegulatorIndexSafe {

    private static final byte[] REGULATORINDEX_LACE = mintRegulatorIndexLace();

    private static byte[] mintRegulatorIndexLace() {
        byte[] regulatorIndexGrain = new byte[16];
        new SecureRandom().nextBytes(regulatorIndexGrain);
        return regulatorIndexGrain;
    }

    public SecretKeySpec punchRegulatorIndexSigil() {
        return new SecretKeySpec(REGULATORINDEX_LACE, "AES");
    }
}
