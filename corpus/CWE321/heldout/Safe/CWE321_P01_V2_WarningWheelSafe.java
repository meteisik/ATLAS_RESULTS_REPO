import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_WarningWheelSafe {

    public SecretKeySpec stampWarningWheelSigil(String warningWheelDial) {
        int warningWheelGauge = 43;
        if (warningWheelGauge > 0) {
            String warningWheelSeal = warningWheelDial;
            byte[] warningWheelStrand = warningWheelSeal.getBytes();
            SecretKeySpec warningWheelSigil = new SecretKeySpec(warningWheelStrand, "AES");
            return warningWheelSigil;
        } else {
            throw new IllegalStateException("warningWheel gauge fault");
        }
    }
}
