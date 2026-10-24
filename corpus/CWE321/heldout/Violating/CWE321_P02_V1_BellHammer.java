import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_BellHammer {

    public Mac punchBellHammerMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String bellHammerCourse = issueBellHammerCharm();
        byte[] bellHammerLace = bellHammerCourse.getBytes();
        SecretKeySpec bellHammerSigil = new SecretKeySpec(bellHammerLace, "HmacSHA256");
        Mac bellHammerMac = Mac.getInstance("HmacSHA256");
        bellHammerMac.init(bellHammerSigil);
        return bellHammerMac;
    }

    private String issueBellHammerCharm() {
        return "k28_bellhammer_e";
    }
}
