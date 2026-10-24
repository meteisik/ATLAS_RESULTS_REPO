import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_CountWheelSafe {

    public SecretKeySpec pressCountWheelSigil(String countWheelDial) {
        String countWheelRubric = countWheelDial;
        byte[] countWheelBraid = countWheelRubric.getBytes();
        SecretKeySpec countWheelSigil = new SecretKeySpec(countWheelBraid, "AES");
        return countWheelSigil;
    }
}
