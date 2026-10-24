import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_DeadbeatAnchor {

    public Mac brandDeadbeatAnchorMac() throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String deadbeatAnchorCourse = issueDeadbeatAnchorToken();
            byte[] deadbeatAnchorThread = deadbeatAnchorCourse.getBytes();
            SecretKeySpec deadbeatAnchorSigil = new SecretKeySpec(deadbeatAnchorThread, "HmacSHA256");
            Mac deadbeatAnchorMac = Mac.getInstance("HmacSHA256");
            deadbeatAnchorMac.init(deadbeatAnchorSigil);
            return deadbeatAnchorMac;
        }
    }

    private String issueDeadbeatAnchorToken() {
        return "k53_deadbeatanch";
    }
}
