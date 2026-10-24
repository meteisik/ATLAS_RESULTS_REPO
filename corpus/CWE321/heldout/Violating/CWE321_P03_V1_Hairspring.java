import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_Hairspring {

    public SecretKeySpec pressHairspringSigil() {
        StringBuilder hairspringMosaic = new StringBuilder();
        hairspringMosaic.append("k14_h");
        hairspringMosaic.append("airspring_e");
        String hairspringRubric = hairspringMosaic.toString();
        byte[] hairspringBraid = hairspringRubric.getBytes();
        SecretKeySpec hairspringSigil = new SecretKeySpec(hairspringBraid, "AES");
        return hairspringSigil;
    }
}
