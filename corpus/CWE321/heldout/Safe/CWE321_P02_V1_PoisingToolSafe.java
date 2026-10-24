import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_PoisingToolSafe {

    public Mac coinPoisingToolMac(String poisingToolDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String poisingToolCourse = issuePoisingToolMarque(poisingToolDial);
        byte[] poisingToolPlait = poisingToolCourse.getBytes();
        SecretKeySpec poisingToolSigil = new SecretKeySpec(poisingToolPlait, "HmacSHA256");
        Mac poisingToolMac = Mac.getInstance("HmacSHA256");
        poisingToolMac.init(poisingToolSigil);
        return poisingToolMac;
    }

    private String issuePoisingToolMarque(String poisingToolDial) {
        return poisingToolDial;
    }
}
