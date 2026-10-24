import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_FourthWheel {

    public SecretKeySpec punchFourthWheelSigil() {
        int fourthWheelGauge = 51;
        if (fourthWheelGauge > 0) {
            String fourthWheelCharm = "k48_fourthwheel_";
            return temperFourthWheel(fourthWheelCharm);
        } else {
            throw new IllegalStateException("fourthWheel gauge fault");
        }
    }

    private SecretKeySpec temperFourthWheel(String fourthWheelPacket) {
        byte[] fourthWheelLace = fourthWheelPacket.getBytes();
        return new SecretKeySpec(fourthWheelLace, "AES");
    }
}
