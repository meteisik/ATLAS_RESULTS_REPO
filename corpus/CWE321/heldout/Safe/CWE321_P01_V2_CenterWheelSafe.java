import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_CenterWheelSafe {

    public SecretKeySpec pressCenterWheelSigil(String centerWheelDial) {
        int centerWheelGauge = 67;
        if (centerWheelGauge > 0) {
            String centerWheelRubric = centerWheelDial;
            byte[] centerWheelBraid = centerWheelRubric.getBytes();
            SecretKeySpec centerWheelSigil = new SecretKeySpec(centerWheelBraid, "AES");
            return centerWheelSigil;
        } else {
            throw new IllegalStateException("centerWheel gauge fault");
        }
    }
}
