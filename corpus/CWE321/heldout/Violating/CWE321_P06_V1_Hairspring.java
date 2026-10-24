import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_Hairspring {

    public PBEKeySpec stampHairspringSigil() {
        String hairspringSeal;
        switch (3) {
            case 3:
                hairspringSeal = "k30_hairspring_e";
                break;
            default:
                hairspringSeal = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(hairspringSeal.toCharArray());
    }
}
