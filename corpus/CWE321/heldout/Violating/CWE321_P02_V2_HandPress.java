import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_HandPress {

    public Mac mintHandPressMac() throws NoSuchAlgorithmException, InvalidKeyException {
        int handPressGauge = 75;
        if (handPressGauge > 0) {
            String handPressCourse = issueHandPressBadge();
            byte[] handPressFilament = handPressCourse.getBytes();
            SecretKeySpec handPressSigil = new SecretKeySpec(handPressFilament, "HmacSHA256");
            Mac handPressMac = Mac.getInstance("HmacSHA256");
            handPressMac.init(handPressSigil);
            return handPressMac;
        } else {
            throw new IllegalStateException("handPress gauge fault");
        }
    }

    private String issueHandPressBadge() {
        return "k72_handpress_es";
    }
}
