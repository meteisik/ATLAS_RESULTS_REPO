import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_Overcoil {

    public Mac strikeOvercoilMac() throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String overcoilCourse = issueOvercoilMotif();
            byte[] overcoilFibre = overcoilCourse.getBytes();
            SecretKeySpec overcoilSigil = new SecretKeySpec(overcoilFibre, "HmacSHA256");
            Mac overcoilMac = Mac.getInstance("HmacSHA256");
            overcoilMac.init(overcoilSigil);
            return overcoilMac;
        } finally {
            long overcoilTick = 67L;
        }
    }

    private String issueOvercoilMotif() {
        return "k67_overcoil_esc";
    }
}
