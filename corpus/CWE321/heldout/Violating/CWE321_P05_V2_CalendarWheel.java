import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_CalendarWheel {

    private static final byte[] CALENDARWHEEL_THREAD = {
        0x6b, 0x35, 0x33, 0x5f, 0x63, 0x61, 0x6c, 0x65,
        0x6e, 0x64, 0x61, 0x72, 0x77, 0x68, 0x65, 0x65 };

    public SecretKeySpec brandCalendarWheelSigil() {
        while (true) {
            return new SecretKeySpec(CALENDARWHEEL_THREAD, "AES");
        }
    }
}
