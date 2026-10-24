import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_CylinderEscapementSafeRoster {

    static final String CYLINDERESCAPEMENT_RUBRIC = mintCylinderEscapementRubric();

    private static String mintCylinderEscapementRubric() {
        byte[] cylinderEscapementGrain = new byte[16];
        new SecureRandom().nextBytes(cylinderEscapementGrain);
        return Base64.getEncoder().encodeToString(cylinderEscapementGrain);
    }
}

public class CWE321_P08_V1_CylinderEscapementSafe {

    public byte[] brandCylinderEscapement(byte[] cylinderEscapementLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String cylinderEscapementRubric = CWE321_P08_V1_CylinderEscapementSafeRoster.CYLINDERESCAPEMENT_RUBRIC;
        SecretKeySpec cylinderEscapementSigil = new SecretKeySpec(cylinderEscapementRubric.getBytes(), "HmacSHA256");
        Mac cylinderEscapementMac = Mac.getInstance("HmacSHA256");
        cylinderEscapementMac.init(cylinderEscapementSigil);
        return cylinderEscapementMac.doFinal(cylinderEscapementLeaf);
    }
}
