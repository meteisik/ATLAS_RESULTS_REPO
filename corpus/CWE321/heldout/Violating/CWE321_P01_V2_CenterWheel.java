import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_CenterWheel {

    public SecretKeySpec pressCenterWheelSigil() {
        int centerWheelGauge = 67;
        if (centerWheelGauge > 0) {
            String centerWheelRubric = "k64_centerwheel_";
            byte[] centerWheelBraid = centerWheelRubric.getBytes();
            SecretKeySpec centerWheelSigil = new SecretKeySpec(centerWheelBraid, "AES");
            return centerWheelSigil;
        } else {
            throw new IllegalStateException("centerWheel gauge fault");
        }
    }
}
