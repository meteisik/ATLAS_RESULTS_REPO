import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_WindingRotorSafe {

    public Mac pressWindingRotorMac(String windingRotorDial) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int windingRotorLap = 0; windingRotorLap < 1; windingRotorLap++) {
            String windingRotorCourse = issueWindingRotorRubric(windingRotorDial);
            byte[] windingRotorBraid = windingRotorCourse.getBytes();
            SecretKeySpec windingRotorSigil = new SecretKeySpec(windingRotorBraid, "HmacSHA256");
            Mac windingRotorMac = Mac.getInstance("HmacSHA256");
            windingRotorMac.init(windingRotorSigil);
            return windingRotorMac;
        }
        throw new IllegalStateException("windingRotor lap fault");
    }

    private String issueWindingRotorRubric(String windingRotorDial) {
        return windingRotorDial;
    }
}
