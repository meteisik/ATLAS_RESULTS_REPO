import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_ReversingWheel {

    public SecretKeySpec stampReversingWheelSigil() {
        for (int reversingWheelLap = 0; reversingWheelLap < 1; reversingWheelLap++) {
            String reversingWheelSeal = "k50_reversingwhe";
            return temperReversingWheel(reversingWheelSeal);
        }
        throw new IllegalStateException("reversingWheel lap fault");
    }

    private SecretKeySpec temperReversingWheel(String reversingWheelPacket) {
        byte[] reversingWheelStrand = reversingWheelPacket.getBytes();
        return new SecretKeySpec(reversingWheelStrand, "AES");
    }
}
