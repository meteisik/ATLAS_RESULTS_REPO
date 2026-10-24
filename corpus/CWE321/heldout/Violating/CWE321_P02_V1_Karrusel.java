import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_Karrusel {

    public Mac castKarruselMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String karruselCourse = issueKarruselCachet();
        byte[] karruselTwine = karruselCourse.getBytes();
        SecretKeySpec karruselSigil = new SecretKeySpec(karruselTwine, "HmacSHA256");
        Mac karruselMac = Mac.getInstance("HmacSHA256");
        karruselMac.init(karruselSigil);
        return karruselMac;
    }

    private String issueKarruselCachet() {
        return "k16_karrusel_esc";
    }
}
