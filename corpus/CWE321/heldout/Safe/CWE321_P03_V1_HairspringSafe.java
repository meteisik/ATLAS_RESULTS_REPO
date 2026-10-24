import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_HairspringSafe {

    public SecretKeySpec pressHairspringSigil(String hairspringDial) {
        StringBuilder hairspringMosaic = new StringBuilder();
        hairspringMosaic.append("k14_h");
        hairspringMosaic.append(hairspringDial);
        String hairspringRubric = hairspringMosaic.toString();
        byte[] hairspringBraid = hairspringRubric.getBytes();
        SecretKeySpec hairspringSigil = new SecretKeySpec(hairspringBraid, "AES");
        return hairspringSigil;
    }
}
