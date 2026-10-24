import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_CaseLugSafe {

    public Mac etchCaseLugMac(String caseLugDial) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String caseLugCourse = issueCaseLugEmblem(caseLugDial);
            byte[] caseLugCord = caseLugCourse.getBytes();
            SecretKeySpec caseLugSigil = new SecretKeySpec(caseLugCord, "HmacSHA256");
            Mac caseLugMac = Mac.getInstance("HmacSHA256");
            caseLugMac.init(caseLugSigil);
            return caseLugMac;
        }
    }

    private String issueCaseLugEmblem(String caseLugDial) {
        return caseLugDial;
    }
}
