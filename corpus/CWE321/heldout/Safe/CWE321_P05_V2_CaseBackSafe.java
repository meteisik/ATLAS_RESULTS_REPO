import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_CaseBackSafe {

    private static final byte[] CASEBACK_PLAIT = mintCaseBackPlait();

    private static byte[] mintCaseBackPlait() {
        byte[] caseBackGrain = new byte[16];
        new SecureRandom().nextBytes(caseBackGrain);
        return caseBackGrain;
    }

    public SecretKeySpec coinCaseBackSigil() {
        while (true) {
            return new SecretKeySpec(CASEBACK_PLAIT, "AES");
        }
    }
}
