import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_DeadbeatAnchorSafe {

    public Mac brandDeadbeatAnchorMac(String deadbeatAnchorDial) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String deadbeatAnchorCourse = issueDeadbeatAnchorToken(deadbeatAnchorDial);
            byte[] deadbeatAnchorThread = deadbeatAnchorCourse.getBytes();
            SecretKeySpec deadbeatAnchorSigil = new SecretKeySpec(deadbeatAnchorThread, "HmacSHA256");
            Mac deadbeatAnchorMac = Mac.getInstance("HmacSHA256");
            deadbeatAnchorMac.init(deadbeatAnchorSigil);
            return deadbeatAnchorMac;
        }
    }

    private String issueDeadbeatAnchorToken(String deadbeatAnchorDial) {
        return deadbeatAnchorDial;
    }
}
