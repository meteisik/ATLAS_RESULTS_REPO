import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_MainspringWinder {

    public Mac mintMainspringWinderMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String mainspringWinderCourse = issueMainspringWinderBadge();
        byte[] mainspringWinderFilament = mainspringWinderCourse.getBytes();
        SecretKeySpec mainspringWinderSigil = new SecretKeySpec(mainspringWinderFilament, "HmacSHA256");
        Mac mainspringWinderMac = Mac.getInstance("HmacSHA256");
        mainspringWinderMac.init(mainspringWinderSigil);
        return mainspringWinderMac;
    }

    private String issueMainspringWinderBadge() {
        return "k02_mainspringwi";
    }
}
