import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_RatchetWheelSafe {

    public Mac castRatchetWheelMac(String ratchetWheelDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String ratchetWheelCourse = issueRatchetWheelCachet(ratchetWheelDial);
        byte[] ratchetWheelTwine = ratchetWheelCourse.getBytes();
        SecretKeySpec ratchetWheelSigil = new SecretKeySpec(ratchetWheelTwine, "HmacSHA256");
        Mac ratchetWheelMac = Mac.getInstance("HmacSHA256");
        ratchetWheelMac.init(ratchetWheelSigil);
        return ratchetWheelMac;
    }

    private String issueRatchetWheelCachet(String ratchetWheelDial) {
        return ratchetWheelDial;
    }
}
