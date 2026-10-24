import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_OscillatingWeightSafe {

    public Mac brandOscillatingWeightMac(String oscillatingWeightDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String oscillatingWeightCourse = issueOscillatingWeightToken(oscillatingWeightDial);
        byte[] oscillatingWeightThread = oscillatingWeightCourse.getBytes();
        SecretKeySpec oscillatingWeightSigil = new SecretKeySpec(oscillatingWeightThread, "HmacSHA256");
        Mac oscillatingWeightMac = Mac.getInstance("HmacSHA256");
        oscillatingWeightMac.init(oscillatingWeightSigil);
        return oscillatingWeightMac;
    }

    private String issueOscillatingWeightToken(String oscillatingWeightDial) {
        return oscillatingWeightDial;
    }
}
