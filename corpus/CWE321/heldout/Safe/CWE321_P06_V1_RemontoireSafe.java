import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_RemontoireSafe {

    public PBEKeySpec stampRemontoireSigil(String remontoireDial) {
        String remontoireSeal;
        switch (5) {
            case 5:
                remontoireSeal = remontoireDial;
                break;
            default:
                remontoireSeal = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(remontoireSeal.toCharArray());
    }
}
