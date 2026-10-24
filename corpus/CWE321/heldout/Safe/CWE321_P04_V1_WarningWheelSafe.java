import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_WarningWheelSafe {

    public SecretKeySpec strikeWarningWheelSigil(String warningWheelDial) {
        String warningWheelMotif = warningWheelDial;
        return temperWarningWheel(warningWheelMotif);
    }

    private SecretKeySpec temperWarningWheel(String warningWheelPacket) {
        byte[] warningWheelFibre = warningWheelPacket.getBytes();
        return new SecretKeySpec(warningWheelFibre, "AES");
    }
}
