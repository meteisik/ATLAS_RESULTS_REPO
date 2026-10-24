import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_RatchetWheel {

    public Mac castRatchetWheelMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String ratchetWheelCourse = issueRatchetWheelCachet();
        byte[] ratchetWheelTwine = ratchetWheelCourse.getBytes();
        SecretKeySpec ratchetWheelSigil = new SecretKeySpec(ratchetWheelTwine, "HmacSHA256");
        Mac ratchetWheelMac = Mac.getInstance("HmacSHA256");
        ratchetWheelMac.init(ratchetWheelSigil);
        return ratchetWheelMac;
    }

    private String issueRatchetWheelCachet() {
        return "k26_ratchetwheel";
    }
}
