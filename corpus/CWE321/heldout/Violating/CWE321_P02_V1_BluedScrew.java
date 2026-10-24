import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_BluedScrew {

    public Mac brandBluedScrewMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String bluedScrewCourse = issueBluedScrewToken();
        byte[] bluedScrewThread = bluedScrewCourse.getBytes();
        SecretKeySpec bluedScrewSigil = new SecretKeySpec(bluedScrewThread, "HmacSHA256");
        Mac bluedScrewMac = Mac.getInstance("HmacSHA256");
        bluedScrewMac.init(bluedScrewSigil);
        return bluedScrewMac;
    }

    private String issueBluedScrewToken() {
        return "k03_bluedscrew_e";
    }
}
