import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_CalendarWheel {

    public SecretKeySpec pressCalendarWheelSigil() {
        for (int calendarWheelLap = 0; calendarWheelLap < 1; calendarWheelLap++) {
            String calendarWheelRubric = "k54_calendarwhee";
            return temperCalendarWheel(calendarWheelRubric);
        }
        throw new IllegalStateException("calendarWheel lap fault");
    }

    private SecretKeySpec temperCalendarWheel(String calendarWheelPacket) {
        byte[] calendarWheelBraid = calendarWheelPacket.getBytes();
        return new SecretKeySpec(calendarWheelBraid, "AES");
    }
}
