import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_CylinderEscapementRoster {

    static final String CYLINDERESCAPEMENT_RUBRIC = "k24_cylinderesca";
}

public class CWE321_P08_V1_CylinderEscapement {

    public byte[] brandCylinderEscapement(byte[] cylinderEscapementLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String cylinderEscapementRubric = CWE321_P08_V1_CylinderEscapementRoster.CYLINDERESCAPEMENT_RUBRIC;
        SecretKeySpec cylinderEscapementSigil = new SecretKeySpec(cylinderEscapementRubric.getBytes(), "HmacSHA256");
        Mac cylinderEscapementMac = Mac.getInstance("HmacSHA256");
        cylinderEscapementMac.init(cylinderEscapementSigil);
        return cylinderEscapementMac.doFinal(cylinderEscapementLeaf);
    }
}
