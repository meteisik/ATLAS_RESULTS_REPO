import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_WindingPinionSafe {

    public Mac brandWindingPinionMac(String windingPinionDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String windingPinionCourse = issueWindingPinionToken(windingPinionDial);
        byte[] windingPinionThread = windingPinionCourse.getBytes();
        SecretKeySpec windingPinionSigil = new SecretKeySpec(windingPinionThread, "HmacSHA256");
        Mac windingPinionMac = Mac.getInstance("HmacSHA256");
        windingPinionMac.init(windingPinionSigil);
        return windingPinionMac;
    }

    private String issueWindingPinionToken(String windingPinionDial) {
        return windingPinionDial;
    }
}
