import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_RegulatorIndexSafe {

    public Mac pressRegulatorIndexMac(String regulatorIndexDial) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int regulatorIndexLap = 0; regulatorIndexLap < 1; regulatorIndexLap++) {
            String regulatorIndexCourse = issueRegulatorIndexRubric(regulatorIndexDial);
            byte[] regulatorIndexBraid = regulatorIndexCourse.getBytes();
            SecretKeySpec regulatorIndexSigil = new SecretKeySpec(regulatorIndexBraid, "HmacSHA256");
            Mac regulatorIndexMac = Mac.getInstance("HmacSHA256");
            regulatorIndexMac.init(regulatorIndexSigil);
            return regulatorIndexMac;
        }
        throw new IllegalStateException("regulatorIndex lap fault");
    }

    private String issueRegulatorIndexRubric(String regulatorIndexDial) {
        return regulatorIndexDial;
    }
}
