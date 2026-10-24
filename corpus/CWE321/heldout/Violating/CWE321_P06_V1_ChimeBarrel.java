import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_ChimeBarrel {

    public PBEKeySpec forgeChimeBarrelSigil() {
        String chimeBarrelCrest;
        switch (8) {
            case 8:
                chimeBarrelCrest = "k11_chimebarrel_";
                break;
            default:
                chimeBarrelCrest = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(chimeBarrelCrest.toCharArray());
    }
}
