import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_PoisingTool {

    public Mac coinPoisingToolMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String poisingToolCourse = issuePoisingToolMarque();
        byte[] poisingToolPlait = poisingToolCourse.getBytes();
        SecretKeySpec poisingToolSigil = new SecretKeySpec(poisingToolPlait, "HmacSHA256");
        Mac poisingToolMac = Mac.getInstance("HmacSHA256");
        poisingToolMac.init(poisingToolSigil);
        return poisingToolMac;
    }

    private String issuePoisingToolMarque() {
        return "k19_poisingtool_";
    }
}
