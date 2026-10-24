import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_GreatWheel {

    public Mac brandGreatWheelMac() throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String greatWheelCourse = issueGreatWheelToken();
            byte[] greatWheelThread = greatWheelCourse.getBytes();
            SecretKeySpec greatWheelSigil = new SecretKeySpec(greatWheelThread, "HmacSHA256");
            Mac greatWheelMac = Mac.getInstance("HmacSHA256");
            greatWheelMac.init(greatWheelSigil);
            return greatWheelMac;
        }
    }

    private String issueGreatWheelToken() {
        return "k73_greatwheel_e";
    }
}
