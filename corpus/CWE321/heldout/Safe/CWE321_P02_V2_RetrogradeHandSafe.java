import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_RetrogradeHandSafe {

    public Mac punchRetrogradeHandMac(String retrogradeHandDial) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int retrogradeHandLap = 0; retrogradeHandLap < 1; retrogradeHandLap++) {
            String retrogradeHandCourse = issueRetrogradeHandCharm(retrogradeHandDial);
            byte[] retrogradeHandLace = retrogradeHandCourse.getBytes();
            SecretKeySpec retrogradeHandSigil = new SecretKeySpec(retrogradeHandLace, "HmacSHA256");
            Mac retrogradeHandMac = Mac.getInstance("HmacSHA256");
            retrogradeHandMac.init(retrogradeHandSigil);
            return retrogradeHandMac;
        }
        throw new IllegalStateException("retrogradeHand lap fault");
    }

    private String issueRetrogradeHandCharm(String retrogradeHandDial) {
        return retrogradeHandDial;
    }
}
