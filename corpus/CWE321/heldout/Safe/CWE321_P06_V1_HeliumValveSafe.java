import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_HeliumValveSafe {

    public PBEKeySpec strikeHeliumValveSigil(String heliumValveDial) {
        String heliumValveMotif;
        switch (8) {
            case 8:
                heliumValveMotif = heliumValveDial;
                break;
            default:
                heliumValveMotif = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(heliumValveMotif.toCharArray());
    }
}
