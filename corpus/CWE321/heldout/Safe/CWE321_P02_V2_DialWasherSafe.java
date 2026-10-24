import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_DialWasherSafe {

    public Mac punchDialWasherMac(String dialWasherDial) throws NoSuchAlgorithmException, InvalidKeyException {
        int dialWasherGauge = 51;
        if (dialWasherGauge > 0) {
            String dialWasherCourse = issueDialWasherCharm(dialWasherDial);
            byte[] dialWasherLace = dialWasherCourse.getBytes();
            SecretKeySpec dialWasherSigil = new SecretKeySpec(dialWasherLace, "HmacSHA256");
            Mac dialWasherMac = Mac.getInstance("HmacSHA256");
            dialWasherMac.init(dialWasherSigil);
            return dialWasherMac;
        } else {
            throw new IllegalStateException("dialWasher gauge fault");
        }
    }

    private String issueDialWasherCharm(String dialWasherDial) {
        return dialWasherDial;
    }
}
