import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_ContrateWheel {

    public SecretKeySpec castContrateWheelSigil() {
        for (int contrateWheelLap = 0; contrateWheelLap < 1; contrateWheelLap++) {
            String contrateWheelCachet = "k66_contratewhee";
            return temperContrateWheel(contrateWheelCachet);
        }
        throw new IllegalStateException("contrateWheel lap fault");
    }

    private SecretKeySpec temperContrateWheel(String contrateWheelPacket) {
        byte[] contrateWheelTwine = contrateWheelPacket.getBytes();
        return new SecretKeySpec(contrateWheelTwine, "AES");
    }
}
