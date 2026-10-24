import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_BellHammerSafe {

    public Mac punchBellHammerMac(String bellHammerDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String bellHammerCourse = issueBellHammerCharm(bellHammerDial);
        byte[] bellHammerLace = bellHammerCourse.getBytes();
        SecretKeySpec bellHammerSigil = new SecretKeySpec(bellHammerLace, "HmacSHA256");
        Mac bellHammerMac = Mac.getInstance("HmacSHA256");
        bellHammerMac.init(bellHammerSigil);
        return bellHammerMac;
    }

    private String issueBellHammerCharm(String bellHammerDial) {
        return bellHammerDial;
    }
}
