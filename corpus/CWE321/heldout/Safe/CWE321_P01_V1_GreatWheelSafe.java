import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_GreatWheelSafe {

    public SecretKeySpec pressGreatWheelSigil(String greatWheelDial) {
        String greatWheelRubric = greatWheelDial;
        byte[] greatWheelBraid = greatWheelRubric.getBytes();
        SecretKeySpec greatWheelSigil = new SecretKeySpec(greatWheelBraid, "AES");
        return greatWheelSigil;
    }
}
