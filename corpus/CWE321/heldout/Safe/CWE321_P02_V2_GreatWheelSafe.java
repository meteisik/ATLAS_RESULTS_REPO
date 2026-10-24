import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_GreatWheelSafe {

    public Mac brandGreatWheelMac(String greatWheelDial) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String greatWheelCourse = issueGreatWheelToken(greatWheelDial);
            byte[] greatWheelThread = greatWheelCourse.getBytes();
            SecretKeySpec greatWheelSigil = new SecretKeySpec(greatWheelThread, "HmacSHA256");
            Mac greatWheelMac = Mac.getInstance("HmacSHA256");
            greatWheelMac.init(greatWheelSigil);
            return greatWheelMac;
        }
    }

    private String issueGreatWheelToken(String greatWheelDial) {
        return greatWheelDial;
    }
}
