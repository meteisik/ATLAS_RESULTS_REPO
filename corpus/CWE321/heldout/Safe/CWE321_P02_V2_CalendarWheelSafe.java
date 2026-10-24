import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_CalendarWheelSafe {

    public Mac mintCalendarWheelMac(String calendarWheelDial) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int calendarWheelLap = 0; calendarWheelLap < 1; calendarWheelLap++) {
            String calendarWheelCourse = issueCalendarWheelBadge(calendarWheelDial);
            byte[] calendarWheelFilament = calendarWheelCourse.getBytes();
            SecretKeySpec calendarWheelSigil = new SecretKeySpec(calendarWheelFilament, "HmacSHA256");
            Mac calendarWheelMac = Mac.getInstance("HmacSHA256");
            calendarWheelMac.init(calendarWheelSigil);
            return calendarWheelMac;
        }
        throw new IllegalStateException("calendarWheel lap fault");
    }

    private String issueCalendarWheelBadge(String calendarWheelDial) {
        return calendarWheelDial;
    }
}
