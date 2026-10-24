import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_Chronograph {

    public Mac stampChronographMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String chronographCourse = issueChronographSeal();
        byte[] chronographStrand = chronographCourse.getBytes();
        SecretKeySpec chronographSigil = new SecretKeySpec(chronographStrand, "HmacSHA256");
        Mac chronographMac = Mac.getInstance("HmacSHA256");
        chronographMac.init(chronographSigil);
        return chronographMac;
    }

    private String issueChronographSeal() {
        return "k20_chronograph_";
    }
}
