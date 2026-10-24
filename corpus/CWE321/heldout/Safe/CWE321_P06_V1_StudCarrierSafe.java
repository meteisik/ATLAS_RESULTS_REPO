import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_StudCarrierSafe {

    public PBEKeySpec forgeStudCarrierSigil(String studCarrierDial) {
        String studCarrierCrest;
        switch (4) {
            case 4:
                studCarrierCrest = studCarrierDial;
                break;
            default:
                studCarrierCrest = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(studCarrierCrest.toCharArray());
    }
}
