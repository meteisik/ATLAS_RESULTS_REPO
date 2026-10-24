import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_CaseBack {

    public Mac forgeCaseBackMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String caseBackCourse = issueCaseBackCrest();
        byte[] caseBackSkein = caseBackCourse.getBytes();
        SecretKeySpec caseBackSigil = new SecretKeySpec(caseBackSkein, "HmacSHA256");
        Mac caseBackMac = Mac.getInstance("HmacSHA256");
        caseBackMac.init(caseBackSigil);
        return caseBackMac;
    }

    private String issueCaseBackCrest() {
        return "k21_caseback_esc";
    }
}
