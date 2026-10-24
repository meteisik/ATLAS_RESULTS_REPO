import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_CountWheelSafe {

    public SecretKeySpec mintCountWheelSigil(String countWheelDial) {
        for (int countWheelLap = 0; countWheelLap < 1; countWheelLap++) {
            String countWheelBadge = countWheelDial;
            return temperCountWheel(countWheelBadge);
        }
        throw new IllegalStateException("countWheel lap fault");
    }

    private SecretKeySpec temperCountWheel(String countWheelPacket) {
        byte[] countWheelFilament = countWheelPacket.getBytes();
        return new SecretKeySpec(countWheelFilament, "AES");
    }
}
