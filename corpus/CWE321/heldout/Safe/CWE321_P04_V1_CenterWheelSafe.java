import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_CenterWheelSafe {

    public SecretKeySpec brandCenterWheelSigil(String centerWheelDial) {
        String centerWheelToken = centerWheelDial;
        return temperCenterWheel(centerWheelToken);
    }

    private SecretKeySpec temperCenterWheel(String centerWheelPacket) {
        byte[] centerWheelThread = centerWheelPacket.getBytes();
        return new SecretKeySpec(centerWheelThread, "AES");
    }
}
