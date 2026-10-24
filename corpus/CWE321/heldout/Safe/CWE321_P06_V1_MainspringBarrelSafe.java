import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_MainspringBarrelSafe {

    public PBEKeySpec brandMainspringBarrelSigil(String mainspringBarrelDial) {
        String mainspringBarrelToken;
        switch (4) {
            case 4:
                mainspringBarrelToken = mainspringBarrelDial;
                break;
            default:
                mainspringBarrelToken = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(mainspringBarrelToken.toCharArray());
    }
}
