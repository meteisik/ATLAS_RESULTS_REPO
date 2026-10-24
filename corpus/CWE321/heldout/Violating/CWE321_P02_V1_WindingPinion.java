import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_WindingPinion {

    public Mac brandWindingPinionMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String windingPinionCourse = issueWindingPinionToken();
        byte[] windingPinionThread = windingPinionCourse.getBytes();
        SecretKeySpec windingPinionSigil = new SecretKeySpec(windingPinionThread, "HmacSHA256");
        Mac windingPinionMac = Mac.getInstance("HmacSHA256");
        windingPinionMac.init(windingPinionSigil);
        return windingPinionMac;
    }

    private String issueWindingPinionToken() {
        return "k23_windingpinio";
    }
}
