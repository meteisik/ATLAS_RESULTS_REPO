import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_SuspensionSpringSafe {

    public SecretKeySpec pressSuspensionSpringSigil(String suspensionSpringDial) {
        for (int suspensionSpringLap = 0; suspensionSpringLap < 1; suspensionSpringLap++) {
            String suspensionSpringRubric = suspensionSpringDial;
            byte[] suspensionSpringBraid = suspensionSpringRubric.getBytes();
            SecretKeySpec suspensionSpringSigil = new SecretKeySpec(suspensionSpringBraid, "AES");
            return suspensionSpringSigil;
        }
        throw new IllegalStateException("suspensionSpring lap fault");
    }
}
