import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_ChronographSafe {

    public Mac stampChronographMac(String chronographDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String chronographCourse = issueChronographSeal(chronographDial);
        byte[] chronographStrand = chronographCourse.getBytes();
        SecretKeySpec chronographSigil = new SecretKeySpec(chronographStrand, "HmacSHA256");
        Mac chronographMac = Mac.getInstance("HmacSHA256");
        chronographMac.init(chronographSigil);
        return chronographMac;
    }

    private String issueChronographSeal(String chronographDial) {
        return chronographDial;
    }
}
