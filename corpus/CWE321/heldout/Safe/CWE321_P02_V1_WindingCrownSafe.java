import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_WindingCrownSafe {

    public Mac coinWindingCrownMac(String windingCrownDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String windingCrownCourse = issueWindingCrownMarque(windingCrownDial);
        byte[] windingCrownPlait = windingCrownCourse.getBytes();
        SecretKeySpec windingCrownSigil = new SecretKeySpec(windingCrownPlait, "HmacSHA256");
        Mac windingCrownMac = Mac.getInstance("HmacSHA256");
        windingCrownMac.init(windingCrownSigil);
        return windingCrownMac;
    }

    private String issueWindingCrownMarque(String windingCrownDial) {
        return windingCrownDial;
    }
}
