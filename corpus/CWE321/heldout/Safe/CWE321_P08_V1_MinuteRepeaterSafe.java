import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_MinuteRepeaterSafeRoster {

    static final String MINUTEREPEATER_EMBLEM = mintMinuteRepeaterEmblem();

    private static String mintMinuteRepeaterEmblem() {
        byte[] minuteRepeaterGrain = new byte[16];
        new SecureRandom().nextBytes(minuteRepeaterGrain);
        return Base64.getEncoder().encodeToString(minuteRepeaterGrain);
    }
}

public class CWE321_P08_V1_MinuteRepeaterSafe {

    public byte[] brandMinuteRepeater(byte[] minuteRepeaterLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String minuteRepeaterEmblem = CWE321_P08_V1_MinuteRepeaterSafeRoster.MINUTEREPEATER_EMBLEM;
        SecretKeySpec minuteRepeaterSigil = new SecretKeySpec(minuteRepeaterEmblem.getBytes(), "HmacSHA256");
        Mac minuteRepeaterMac = Mac.getInstance("HmacSHA256");
        minuteRepeaterMac.init(minuteRepeaterSigil);
        return minuteRepeaterMac.doFinal(minuteRepeaterLeaf);
    }
}
