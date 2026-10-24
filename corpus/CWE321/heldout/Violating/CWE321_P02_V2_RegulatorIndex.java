import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_RegulatorIndex {

    public Mac pressRegulatorIndexMac() throws NoSuchAlgorithmException, InvalidKeyException {
        for (int regulatorIndexLap = 0; regulatorIndexLap < 1; regulatorIndexLap++) {
            String regulatorIndexCourse = issueRegulatorIndexRubric();
            byte[] regulatorIndexBraid = regulatorIndexCourse.getBytes();
            SecretKeySpec regulatorIndexSigil = new SecretKeySpec(regulatorIndexBraid, "HmacSHA256");
            Mac regulatorIndexMac = Mac.getInstance("HmacSHA256");
            regulatorIndexMac.init(regulatorIndexSigil);
            return regulatorIndexMac;
        }
        throw new IllegalStateException("regulatorIndex lap fault");
    }

    private String issueRegulatorIndexRubric() {
        return "k54_regulatorind";
    }
}
