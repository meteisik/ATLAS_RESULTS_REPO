import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_CaseBackSafe {

    public Mac forgeCaseBackMac(String caseBackDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String caseBackCourse = issueCaseBackCrest(caseBackDial);
        byte[] caseBackSkein = caseBackCourse.getBytes();
        SecretKeySpec caseBackSigil = new SecretKeySpec(caseBackSkein, "HmacSHA256");
        Mac caseBackMac = Mac.getInstance("HmacSHA256");
        caseBackMac.init(caseBackSigil);
        return caseBackMac;
    }

    private String issueCaseBackCrest(String caseBackDial) {
        return caseBackDial;
    }
}
