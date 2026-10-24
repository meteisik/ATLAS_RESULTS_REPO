import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_CylinderEscapementSafe {

    public Mac etchCylinderEscapementMac(String cylinderEscapementDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String cylinderEscapementCourse = issueCylinderEscapementEmblem(cylinderEscapementDial);
        byte[] cylinderEscapementCord = cylinderEscapementCourse.getBytes();
        SecretKeySpec cylinderEscapementSigil = new SecretKeySpec(cylinderEscapementCord, "HmacSHA256");
        Mac cylinderEscapementMac = Mac.getInstance("HmacSHA256");
        cylinderEscapementMac.init(cylinderEscapementSigil);
        return cylinderEscapementMac;
    }

    private String issueCylinderEscapementEmblem(String cylinderEscapementDial) {
        return cylinderEscapementDial;
    }
}
