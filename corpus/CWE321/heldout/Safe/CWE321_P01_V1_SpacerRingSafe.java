import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_SpacerRingSafe {

    public SecretKeySpec pressSpacerRingSigil(String spacerRingDial) {
        String spacerRingRubric = spacerRingDial;
        byte[] spacerRingBraid = spacerRingRubric.getBytes();
        SecretKeySpec spacerRingSigil = new SecretKeySpec(spacerRingBraid, "AES");
        return spacerRingSigil;
    }
}
