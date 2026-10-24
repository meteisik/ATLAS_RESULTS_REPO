import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_CenterWheel {

    public SecretKeySpec brandCenterWheelSigil() {
        String centerWheelToken = "k33_centerwheel_";
        return temperCenterWheel(centerWheelToken);
    }

    private SecretKeySpec temperCenterWheel(String centerWheelPacket) {
        byte[] centerWheelThread = centerWheelPacket.getBytes();
        return new SecretKeySpec(centerWheelThread, "AES");
    }
}
