import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_CountWheel {

    public SecretKeySpec mintCountWheelSigil() {
        for (int countWheelLap = 0; countWheelLap < 1; countWheelLap++) {
            String countWheelBadge = "k42_countwheel_e";
            return temperCountWheel(countWheelBadge);
        }
        throw new IllegalStateException("countWheel lap fault");
    }

    private SecretKeySpec temperCountWheel(String countWheelPacket) {
        byte[] countWheelFilament = countWheelPacket.getBytes();
        return new SecretKeySpec(countWheelFilament, "AES");
    }
}
