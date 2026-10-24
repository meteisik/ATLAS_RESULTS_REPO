import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_StudCarrier {

    public PBEKeySpec forgeStudCarrierSigil() {
        String studCarrierCrest;
        switch (4) {
            case 4:
                studCarrierCrest = "k01_studcarrier_";
                break;
            default:
                studCarrierCrest = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(studCarrierCrest.toCharArray());
    }
}
