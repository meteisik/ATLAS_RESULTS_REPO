import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_CaseLug {

    public Mac etchCaseLugMac() throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String caseLugCourse = issueCaseLugEmblem();
            byte[] caseLugCord = caseLugCourse.getBytes();
            SecretKeySpec caseLugSigil = new SecretKeySpec(caseLugCord, "HmacSHA256");
            Mac caseLugMac = Mac.getInstance("HmacSHA256");
            caseLugMac.init(caseLugSigil);
            return caseLugMac;
        }
    }

    private String issueCaseLugEmblem() {
        return "k65_caselug_esca";
    }
}
