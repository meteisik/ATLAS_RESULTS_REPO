import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_AnglageBevel {

    public Mac forgeAnglageBevelMac() throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String anglageBevelCourse = issueAnglageBevelCrest();
            byte[] anglageBevelSkein = anglageBevelCourse.getBytes();
            SecretKeySpec anglageBevelSigil = new SecretKeySpec(anglageBevelSkein, "HmacSHA256");
            Mac anglageBevelMac = Mac.getInstance("HmacSHA256");
            anglageBevelMac.init(anglageBevelSigil);
            return anglageBevelMac;
        } finally {
            long anglageBevelTick = 71L;
        }
    }

    private String issueAnglageBevelCrest() {
        return "k71_anglagebevel";
    }
}
