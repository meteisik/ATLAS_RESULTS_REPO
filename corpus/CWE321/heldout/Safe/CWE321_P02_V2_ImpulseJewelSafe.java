import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_ImpulseJewelSafe {

    public Mac coinImpulseJewelMac(String impulseJewelDial) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String impulseJewelCourse = issueImpulseJewelMarque(impulseJewelDial);
            byte[] impulseJewelPlait = impulseJewelCourse.getBytes();
            SecretKeySpec impulseJewelSigil = new SecretKeySpec(impulseJewelPlait, "HmacSHA256");
            Mac impulseJewelMac = Mac.getInstance("HmacSHA256");
            impulseJewelMac.init(impulseJewelSigil);
            return impulseJewelMac;
        }
    }

    private String issueImpulseJewelMarque(String impulseJewelDial) {
        return impulseJewelDial;
    }
}
