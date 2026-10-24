import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_MinuteRepeaterRoster {

    static final String MINUTEREPEATER_EMBLEM = "k25_minuterepeat";
}

public class CWE321_P08_V1_MinuteRepeater {

    public byte[] brandMinuteRepeater(byte[] minuteRepeaterLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String minuteRepeaterEmblem = CWE321_P08_V1_MinuteRepeaterRoster.MINUTEREPEATER_EMBLEM;
        SecretKeySpec minuteRepeaterSigil = new SecretKeySpec(minuteRepeaterEmblem.getBytes(), "HmacSHA256");
        Mac minuteRepeaterMac = Mac.getInstance("HmacSHA256");
        minuteRepeaterMac.init(minuteRepeaterSigil);
        return minuteRepeaterMac.doFinal(minuteRepeaterLeaf);
    }
}
