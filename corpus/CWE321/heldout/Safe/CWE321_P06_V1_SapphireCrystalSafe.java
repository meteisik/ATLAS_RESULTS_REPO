import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_SapphireCrystalSafe {

    public PBEKeySpec strikeSapphireCrystalSigil(String sapphireCrystalDial) {
        String sapphireCrystalMotif;
        switch (6) {
            case 6:
                sapphireCrystalMotif = sapphireCrystalDial;
                break;
            default:
                sapphireCrystalMotif = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(sapphireCrystalMotif.toCharArray());
    }
}
