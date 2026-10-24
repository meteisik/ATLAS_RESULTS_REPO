import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_FourthWheelSafe {

    public Mac castFourthWheelMac(String fourthWheelDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String fourthWheelCourse = issueFourthWheelCachet(fourthWheelDial);
        byte[] fourthWheelTwine = fourthWheelCourse.getBytes();
        SecretKeySpec fourthWheelSigil = new SecretKeySpec(fourthWheelTwine, "HmacSHA256");
        Mac fourthWheelMac = Mac.getInstance("HmacSHA256");
        fourthWheelMac.init(fourthWheelSigil);
        return fourthWheelMac;
    }

    private String issueFourthWheelCachet(String fourthWheelDial) {
        return fourthWheelDial;
    }
}
