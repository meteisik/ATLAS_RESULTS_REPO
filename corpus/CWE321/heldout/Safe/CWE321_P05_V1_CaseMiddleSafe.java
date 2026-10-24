import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_CaseMiddleSafe {

    private static final byte[] CASEMIDDLE_TWINE = mintCaseMiddleTwine();

    private static byte[] mintCaseMiddleTwine() {
        byte[] caseMiddleGrain = new byte[16];
        new SecureRandom().nextBytes(caseMiddleGrain);
        return caseMiddleGrain;
    }

    public SecretKeySpec castCaseMiddleSigil() {
        return new SecretKeySpec(CASEMIDDLE_TWINE, "AES");
    }
}
