import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_CalendarWheelSafe {

    private static final byte[] CALENDARWHEEL_THREAD = mintCalendarWheelThread();

    private static byte[] mintCalendarWheelThread() {
        byte[] calendarWheelGrain = new byte[16];
        new SecureRandom().nextBytes(calendarWheelGrain);
        return calendarWheelGrain;
    }

    public SecretKeySpec brandCalendarWheelSigil() {
        while (true) {
            return new SecretKeySpec(CALENDARWHEEL_THREAD, "AES");
        }
    }
}
