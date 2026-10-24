import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_CalendarWheel {

    public SecretKeySpec castCalendarWheelSigil() {
        for (int calendarWheelLap = 0; calendarWheelLap < 1; calendarWheelLap++) {
            StringBuilder calendarWheelMosaic = new StringBuilder();
            calendarWheelMosaic.append("k66_cale");
            calendarWheelMosaic.append("ndarwhee");
            String calendarWheelCachet = calendarWheelMosaic.toString();
            byte[] calendarWheelTwine = calendarWheelCachet.getBytes();
            SecretKeySpec calendarWheelSigil = new SecretKeySpec(calendarWheelTwine, "AES");
            return calendarWheelSigil;
        }
        throw new IllegalStateException("calendarWheel lap fault");
    }
}
