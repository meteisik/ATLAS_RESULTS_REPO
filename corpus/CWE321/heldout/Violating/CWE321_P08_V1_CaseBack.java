import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_CaseBackRoster {

    static final String CASEBACK_CACHET = "k16_caseback_esc";
}

public class CWE321_P08_V1_CaseBack {

    public byte[] brandCaseBack(byte[] caseBackLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String caseBackCachet = CWE321_P08_V1_CaseBackRoster.CASEBACK_CACHET;
        SecretKeySpec caseBackSigil = new SecretKeySpec(caseBackCachet.getBytes(), "HmacSHA256");
        Mac caseBackMac = Mac.getInstance("HmacSHA256");
        caseBackMac.init(caseBackSigil);
        return caseBackMac.doFinal(caseBackLeaf);
    }
}
