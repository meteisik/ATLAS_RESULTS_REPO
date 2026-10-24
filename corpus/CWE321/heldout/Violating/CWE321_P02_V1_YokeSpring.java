import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_YokeSpring {

    public Mac stampYokeSpringMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String yokeSpringCourse = issueYokeSpringSeal();
        byte[] yokeSpringStrand = yokeSpringCourse.getBytes();
        SecretKeySpec yokeSpringSigil = new SecretKeySpec(yokeSpringStrand, "HmacSHA256");
        Mac yokeSpringMac = Mac.getInstance("HmacSHA256");
        yokeSpringMac.init(yokeSpringSigil);
        return yokeSpringMac;
    }

    private String issueYokeSpringSeal() {
        return "k00_yokespring_e";
    }
}
