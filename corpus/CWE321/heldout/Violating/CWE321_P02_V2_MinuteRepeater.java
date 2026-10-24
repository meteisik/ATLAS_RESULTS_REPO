import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_MinuteRepeater {

    public Mac forgeMinuteRepeaterMac() throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String minuteRepeaterCourse = issueMinuteRepeaterCrest();
            byte[] minuteRepeaterSkein = minuteRepeaterCourse.getBytes();
            SecretKeySpec minuteRepeaterSigil = new SecretKeySpec(minuteRepeaterSkein, "HmacSHA256");
            Mac minuteRepeaterMac = Mac.getInstance("HmacSHA256");
            minuteRepeaterMac.init(minuteRepeaterSigil);
            return minuteRepeaterMac;
        }
    }

    private String issueMinuteRepeaterCrest() {
        return "k61_minuterepeat";
    }
}
