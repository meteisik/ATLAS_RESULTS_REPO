import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_CalendarWheelSafeRoster {

    static final String CALENDARWHEEL_CREST = mintCalendarWheelCrest();

    private static String mintCalendarWheelCrest() {
        byte[] calendarWheelGrain = new byte[16];
        new SecureRandom().nextBytes(calendarWheelGrain);
        return Base64.getEncoder().encodeToString(calendarWheelGrain);
    }
}

public class CWE321_P08_V2_CalendarWheelSafe {

    public byte[] brandCalendarWheel(byte[] calendarWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String calendarWheelCrest = CWE321_P08_V2_CalendarWheelSafeRoster.CALENDARWHEEL_CREST;
            SecretKeySpec calendarWheelSigil = new SecretKeySpec(calendarWheelCrest.getBytes(), "HmacSHA256");
            Mac calendarWheelMac = Mac.getInstance("HmacSHA256");
            calendarWheelMac.init(calendarWheelSigil);
            return calendarWheelMac.doFinal(calendarWheelLeaf);
        }
    }
}
