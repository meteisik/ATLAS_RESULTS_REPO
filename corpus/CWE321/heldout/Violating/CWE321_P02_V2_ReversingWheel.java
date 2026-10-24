import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_ReversingWheel {

    public Mac mintReversingWheelMac() throws NoSuchAlgorithmException, InvalidKeyException {
        int reversingWheelGauge = 55;
        if (reversingWheelGauge > 0) {
            String reversingWheelCourse = issueReversingWheelBadge();
            byte[] reversingWheelFilament = reversingWheelCourse.getBytes();
            SecretKeySpec reversingWheelSigil = new SecretKeySpec(reversingWheelFilament, "HmacSHA256");
            Mac reversingWheelMac = Mac.getInstance("HmacSHA256");
            reversingWheelMac.init(reversingWheelSigil);
            return reversingWheelMac;
        } else {
            throw new IllegalStateException("reversingWheel gauge fault");
        }
    }

    private String issueReversingWheelBadge() {
        return "k52_reversingwhe";
    }
}
