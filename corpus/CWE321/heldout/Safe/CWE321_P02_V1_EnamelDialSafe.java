import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_EnamelDialSafe {

    public Mac forgeEnamelDialMac(String enamelDialDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String enamelDialCourse = issueEnamelDialCrest(enamelDialDial);
        byte[] enamelDialSkein = enamelDialCourse.getBytes();
        SecretKeySpec enamelDialSigil = new SecretKeySpec(enamelDialSkein, "HmacSHA256");
        Mac enamelDialMac = Mac.getInstance("HmacSHA256");
        enamelDialMac.init(enamelDialSigil);
        return enamelDialMac;
    }

    private String issueEnamelDialCrest(String enamelDialDial) {
        return enamelDialDial;
    }
}
