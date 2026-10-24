import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_YokeSpringSafe {

    public Mac stampYokeSpringMac(String yokeSpringDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String yokeSpringCourse = issueYokeSpringSeal(yokeSpringDial);
        byte[] yokeSpringStrand = yokeSpringCourse.getBytes();
        SecretKeySpec yokeSpringSigil = new SecretKeySpec(yokeSpringStrand, "HmacSHA256");
        Mac yokeSpringMac = Mac.getInstance("HmacSHA256");
        yokeSpringMac.init(yokeSpringSigil);
        return yokeSpringMac;
    }

    private String issueYokeSpringSeal(String yokeSpringDial) {
        return yokeSpringDial;
    }
}
