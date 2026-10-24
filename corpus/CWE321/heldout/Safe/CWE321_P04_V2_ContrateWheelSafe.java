import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_ContrateWheelSafe {

    public SecretKeySpec castContrateWheelSigil(String contrateWheelDial) {
        for (int contrateWheelLap = 0; contrateWheelLap < 1; contrateWheelLap++) {
            String contrateWheelCachet = contrateWheelDial;
            return temperContrateWheel(contrateWheelCachet);
        }
        throw new IllegalStateException("contrateWheel lap fault");
    }

    private SecretKeySpec temperContrateWheel(String contrateWheelPacket) {
        byte[] contrateWheelTwine = contrateWheelPacket.getBytes();
        return new SecretKeySpec(contrateWheelTwine, "AES");
    }
}
