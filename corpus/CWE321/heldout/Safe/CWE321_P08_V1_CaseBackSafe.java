import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_CaseBackSafeRoster {

    static final String CASEBACK_CACHET = mintCaseBackCachet();

    private static String mintCaseBackCachet() {
        byte[] caseBackGrain = new byte[16];
        new SecureRandom().nextBytes(caseBackGrain);
        return Base64.getEncoder().encodeToString(caseBackGrain);
    }
}

public class CWE321_P08_V1_CaseBackSafe {

    public byte[] brandCaseBack(byte[] caseBackLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String caseBackCachet = CWE321_P08_V1_CaseBackSafeRoster.CASEBACK_CACHET;
        SecretKeySpec caseBackSigil = new SecretKeySpec(caseBackCachet.getBytes(), "HmacSHA256");
        Mac caseBackMac = Mac.getInstance("HmacSHA256");
        caseBackMac.init(caseBackSigil);
        return caseBackMac.doFinal(caseBackLeaf);
    }
}
