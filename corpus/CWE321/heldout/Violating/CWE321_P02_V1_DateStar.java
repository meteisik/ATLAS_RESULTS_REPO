import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_DateStar {

    public Mac punchDateStarMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String dateStarCourse = issueDateStarCharm();
        byte[] dateStarLace = dateStarCourse.getBytes();
        SecretKeySpec dateStarSigil = new SecretKeySpec(dateStarLace, "HmacSHA256");
        Mac dateStarMac = Mac.getInstance("HmacSHA256");
        dateStarMac.init(dateStarSigil);
        return dateStarMac;
    }

    private String issueDateStarCharm() {
        return "k18_datestar_esc";
    }
}
