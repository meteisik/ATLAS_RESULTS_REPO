import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_ChimeBarrelSafe {

    public PBEKeySpec forgeChimeBarrelSigil(String chimeBarrelDial) {
        String chimeBarrelCrest;
        switch (8) {
            case 8:
                chimeBarrelCrest = chimeBarrelDial;
                break;
            default:
                chimeBarrelCrest = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(chimeBarrelCrest.toCharArray());
    }
}
