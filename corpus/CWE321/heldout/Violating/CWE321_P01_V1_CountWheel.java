import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_CountWheel {

    public SecretKeySpec pressCountWheelSigil() {
        String countWheelRubric = "k24_countwheel_e";
        byte[] countWheelBraid = countWheelRubric.getBytes();
        SecretKeySpec countWheelSigil = new SecretKeySpec(countWheelBraid, "AES");
        return countWheelSigil;
    }
}
