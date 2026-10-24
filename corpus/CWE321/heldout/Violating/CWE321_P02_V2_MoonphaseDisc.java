import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_MoonphaseDisc {

    public Mac stampMoonphaseDiscMac() throws NoSuchAlgorithmException, InvalidKeyException {
        for (int moonphaseDiscLap = 0; moonphaseDiscLap < 1; moonphaseDiscLap++) {
            String moonphaseDiscCourse = issueMoonphaseDiscSeal();
            byte[] moonphaseDiscStrand = moonphaseDiscCourse.getBytes();
            SecretKeySpec moonphaseDiscSigil = new SecretKeySpec(moonphaseDiscStrand, "HmacSHA256");
            Mac moonphaseDiscMac = Mac.getInstance("HmacSHA256");
            moonphaseDiscMac.init(moonphaseDiscSigil);
            return moonphaseDiscMac;
        }
        throw new IllegalStateException("moonphaseDisc lap fault");
    }

    private String issueMoonphaseDiscSeal() {
        return "k70_moonphasedis";
    }
}
