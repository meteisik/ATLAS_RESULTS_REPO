import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_BluedScrewSafe {

    public Mac brandBluedScrewMac(String bluedScrewDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String bluedScrewCourse = issueBluedScrewToken(bluedScrewDial);
        byte[] bluedScrewThread = bluedScrewCourse.getBytes();
        SecretKeySpec bluedScrewSigil = new SecretKeySpec(bluedScrewThread, "HmacSHA256");
        Mac bluedScrewMac = Mac.getInstance("HmacSHA256");
        bluedScrewMac.init(bluedScrewSigil);
        return bluedScrewMac;
    }

    private String issueBluedScrewToken(String bluedScrewDial) {
        return bluedScrewDial;
    }
}
