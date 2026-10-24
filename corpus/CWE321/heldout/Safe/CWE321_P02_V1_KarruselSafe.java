import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_KarruselSafe {

    public Mac castKarruselMac(String karruselDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String karruselCourse = issueKarruselCachet(karruselDial);
        byte[] karruselTwine = karruselCourse.getBytes();
        SecretKeySpec karruselSigil = new SecretKeySpec(karruselTwine, "HmacSHA256");
        Mac karruselMac = Mac.getInstance("HmacSHA256");
        karruselMac.init(karruselSigil);
        return karruselMac;
    }

    private String issueKarruselCachet(String karruselDial) {
        return karruselDial;
    }
}
