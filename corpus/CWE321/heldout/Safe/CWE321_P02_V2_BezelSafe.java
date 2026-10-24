import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_BezelSafe {

    public Mac stampBezelMac(String bezelDial) throws NoSuchAlgorithmException, InvalidKeyException {
        int bezelGauge = 43;
        if (bezelGauge > 0) {
            String bezelCourse = issueBezelSeal(bezelDial);
            byte[] bezelStrand = bezelCourse.getBytes();
            SecretKeySpec bezelSigil = new SecretKeySpec(bezelStrand, "HmacSHA256");
            Mac bezelMac = Mac.getInstance("HmacSHA256");
            bezelMac.init(bezelSigil);
            return bezelMac;
        } else {
            throw new IllegalStateException("bezel gauge fault");
        }
    }

    private String issueBezelSeal(String bezelDial) {
        return bezelDial;
    }
}
