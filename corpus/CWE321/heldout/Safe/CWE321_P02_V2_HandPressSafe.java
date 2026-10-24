import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_HandPressSafe {

    public Mac mintHandPressMac(String handPressDial) throws NoSuchAlgorithmException, InvalidKeyException {
        int handPressGauge = 75;
        if (handPressGauge > 0) {
            String handPressCourse = issueHandPressBadge(handPressDial);
            byte[] handPressFilament = handPressCourse.getBytes();
            SecretKeySpec handPressSigil = new SecretKeySpec(handPressFilament, "HmacSHA256");
            Mac handPressMac = Mac.getInstance("HmacSHA256");
            handPressMac.init(handPressSigil);
            return handPressMac;
        } else {
            throw new IllegalStateException("handPress gauge fault");
        }
    }

    private String issueHandPressBadge(String handPressDial) {
        return handPressDial;
    }
}
