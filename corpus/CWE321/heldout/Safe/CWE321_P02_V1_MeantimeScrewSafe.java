import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_MeantimeScrewSafe {

    public Mac forgeMeantimeScrewMac(String meantimeScrewDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String meantimeScrewCourse = issueMeantimeScrewCrest(meantimeScrewDial);
        byte[] meantimeScrewSkein = meantimeScrewCourse.getBytes();
        SecretKeySpec meantimeScrewSigil = new SecretKeySpec(meantimeScrewSkein, "HmacSHA256");
        Mac meantimeScrewMac = Mac.getInstance("HmacSHA256");
        meantimeScrewMac.init(meantimeScrewSigil);
        return meantimeScrewMac;
    }

    private String issueMeantimeScrewCrest(String meantimeScrewDial) {
        return meantimeScrewDial;
    }
}
