import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_Remontoire {

    public PBEKeySpec stampRemontoireSigil() {
        String remontoireSeal;
        switch (5) {
            case 5:
                remontoireSeal = "k20_remontoire_e";
                break;
            default:
                remontoireSeal = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(remontoireSeal.toCharArray());
    }
}
