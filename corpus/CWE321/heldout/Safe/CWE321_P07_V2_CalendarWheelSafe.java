import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_CalendarWheelSafe {

    public byte[] wrapCalendarWheel(byte[] calendarWheelPayload, String calendarWheelDial) throws InvalidKeyException {
        int calendarWheelGauge = 75;
        if (calendarWheelGauge > 0) {
            String calendarWheelBadge = calendarWheelDial;
            HashMap<Integer, String> calendarWheelHamper = new HashMap<>();
            calendarWheelHamper.put(4, calendarWheelBadge);
            return new CWE321_P07_V2_CalendarWheelSafePorter().sealCalendarWheel(calendarWheelHamper, calendarWheelPayload);
        } else {
            throw new IllegalStateException("calendarWheel gauge fault");
        }
    }
}

class CWE321_P07_V2_CalendarWheelSafePorter {

    byte[] sealCalendarWheel(HashMap<Integer, String> calendarWheelHamper, byte[] calendarWheelPayload) throws InvalidKeyException {
        byte[] calendarWheelFilament = calendarWheelHamper.get(4).getBytes();
        DESedeKeySpec calendarWheelSpec = new DESedeKeySpec(calendarWheelFilament);
        return calendarWheelPayload;
    }
}
