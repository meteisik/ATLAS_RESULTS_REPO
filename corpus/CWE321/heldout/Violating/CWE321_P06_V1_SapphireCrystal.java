import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_SapphireCrystal {

    public PBEKeySpec strikeSapphireCrystalSigil() {
        String sapphireCrystalMotif;
        switch (6) {
            case 6:
                sapphireCrystalMotif = "k27_sapphirecrys";
                break;
            default:
                sapphireCrystalMotif = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(sapphireCrystalMotif.toCharArray());
    }
}
