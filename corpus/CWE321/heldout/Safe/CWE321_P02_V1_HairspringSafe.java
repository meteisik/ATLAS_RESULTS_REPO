import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_HairspringSafe {

    public Mac mintHairspringMac(String hairspringDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String hairspringCourse = issueHairspringBadge(hairspringDial);
        byte[] hairspringFilament = hairspringCourse.getBytes();
        SecretKeySpec hairspringSigil = new SecretKeySpec(hairspringFilament, "HmacSHA256");
        Mac hairspringMac = Mac.getInstance("HmacSHA256");
        hairspringMac.init(hairspringSigil);
        return hairspringMac;
    }

    private String issueHairspringBadge(String hairspringDial) {
        return hairspringDial;
    }
}
