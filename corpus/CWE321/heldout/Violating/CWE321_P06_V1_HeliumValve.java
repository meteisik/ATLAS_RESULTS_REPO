import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_HeliumValve {

    public PBEKeySpec strikeHeliumValveSigil() {
        String heliumValveMotif;
        switch (8) {
            case 8:
                heliumValveMotif = "k17_heliumvalve_";
                break;
            default:
                heliumValveMotif = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(heliumValveMotif.toCharArray());
    }
}
