import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_SpacerRing {

    public SecretKeySpec pressSpacerRingSigil() {
        String spacerRingRubric = "k14_spacerring_e";
        byte[] spacerRingBraid = spacerRingRubric.getBytes();
        SecretKeySpec spacerRingSigil = new SecretKeySpec(spacerRingBraid, "AES");
        return spacerRingSigil;
    }
}
