import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_DateStarSafe {

    public Mac punchDateStarMac(String dateStarDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String dateStarCourse = issueDateStarCharm(dateStarDial);
        byte[] dateStarLace = dateStarCourse.getBytes();
        SecretKeySpec dateStarSigil = new SecretKeySpec(dateStarLace, "HmacSHA256");
        Mac dateStarMac = Mac.getInstance("HmacSHA256");
        dateStarMac.init(dateStarSigil);
        return dateStarMac;
    }

    private String issueDateStarCharm(String dateStarDial) {
        return dateStarDial;
    }
}
