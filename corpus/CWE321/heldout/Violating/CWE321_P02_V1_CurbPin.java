import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_CurbPin {

    public Mac etchCurbPinMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String curbPinCourse = issueCurbPinEmblem();
        byte[] curbPinCord = curbPinCourse.getBytes();
        SecretKeySpec curbPinSigil = new SecretKeySpec(curbPinCord, "HmacSHA256");
        Mac curbPinMac = Mac.getInstance("HmacSHA256");
        curbPinMac.init(curbPinSigil);
        return curbPinMac;
    }

    private String issueCurbPinEmblem() {
        return "k35_curbpin_esca";
    }
}
