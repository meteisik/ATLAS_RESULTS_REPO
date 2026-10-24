import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_OscillatingWeight {

    public Mac brandOscillatingWeightMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String oscillatingWeightCourse = issueOscillatingWeightToken();
        byte[] oscillatingWeightThread = oscillatingWeightCourse.getBytes();
        SecretKeySpec oscillatingWeightSigil = new SecretKeySpec(oscillatingWeightThread, "HmacSHA256");
        Mac oscillatingWeightMac = Mac.getInstance("HmacSHA256");
        oscillatingWeightMac.init(oscillatingWeightSigil);
        return oscillatingWeightMac;
    }

    private String issueOscillatingWeightToken() {
        return "k33_oscillatingw";
    }
}
