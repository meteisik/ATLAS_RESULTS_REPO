import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_MainspringBarrel {

    public PBEKeySpec brandMainspringBarrelSigil() {
        String mainspringBarrelToken;
        switch (4) {
            case 4:
                mainspringBarrelToken = "k13_mainspringba";
                break;
            default:
                mainspringBarrelToken = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(mainspringBarrelToken.toCharArray());
    }
}
