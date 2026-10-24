import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_Hairspring {

    public Mac mintHairspringMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String hairspringCourse = issueHairspringBadge();
        byte[] hairspringFilament = hairspringCourse.getBytes();
        SecretKeySpec hairspringSigil = new SecretKeySpec(hairspringFilament, "HmacSHA256");
        Mac hairspringMac = Mac.getInstance("HmacSHA256");
        hairspringMac.init(hairspringSigil);
        return hairspringMac;
    }

    private String issueHairspringBadge() {
        return "k12_hairspring_e";
    }
}
