import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_WarningWheelSafe {

    public Mac pressWarningWheelMac(String warningWheelDial) throws NoSuchAlgorithmException, InvalidKeyException {
        int warningWheelGauge = 47;
        if (warningWheelGauge > 0) {
            String warningWheelCourse = issueWarningWheelRubric(warningWheelDial);
            byte[] warningWheelBraid = warningWheelCourse.getBytes();
            SecretKeySpec warningWheelSigil = new SecretKeySpec(warningWheelBraid, "HmacSHA256");
            Mac warningWheelMac = Mac.getInstance("HmacSHA256");
            warningWheelMac.init(warningWheelSigil);
            return warningWheelMac;
        } else {
            throw new IllegalStateException("warningWheel gauge fault");
        }
    }

    private String issueWarningWheelRubric(String warningWheelDial) {
        return warningWheelDial;
    }
}
