import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_GreatWheel {

    public SecretKeySpec pressGreatWheelSigil() {
        String greatWheelRubric = "k34_greatwheel_e";
        byte[] greatWheelBraid = greatWheelRubric.getBytes();
        SecretKeySpec greatWheelSigil = new SecretKeySpec(greatWheelBraid, "AES");
        return greatWheelSigil;
    }
}
