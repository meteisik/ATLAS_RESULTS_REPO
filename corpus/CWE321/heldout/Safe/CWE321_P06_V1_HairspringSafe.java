import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_HairspringSafe {

    public PBEKeySpec stampHairspringSigil(String hairspringDial) {
        String hairspringSeal;
        switch (3) {
            case 3:
                hairspringSeal = hairspringDial;
                break;
            default:
                hairspringSeal = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(hairspringSeal.toCharArray());
    }
}
