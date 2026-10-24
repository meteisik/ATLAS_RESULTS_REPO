import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_WarningWheel {

    public SecretKeySpec strikeWarningWheelSigil() {
        String warningWheelMotif = "k37_warningwheel";
        return temperWarningWheel(warningWheelMotif);
    }

    private SecretKeySpec temperWarningWheel(String warningWheelPacket) {
        byte[] warningWheelFibre = warningWheelPacket.getBytes();
        return new SecretKeySpec(warningWheelFibre, "AES");
    }
}
