import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_ShockSpringSafe {

    public Mac pressShockSpringMac(String shockSpringDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String shockSpringCourse = issueShockSpringRubric(shockSpringDial);
        byte[] shockSpringBraid = shockSpringCourse.getBytes();
        SecretKeySpec shockSpringSigil = new SecretKeySpec(shockSpringBraid, "HmacSHA256");
        Mac shockSpringMac = Mac.getInstance("HmacSHA256");
        shockSpringMac.init(shockSpringSigil);
        return shockSpringMac;
    }

    private String issueShockSpringRubric(String shockSpringDial) {
        return shockSpringDial;
    }
}
