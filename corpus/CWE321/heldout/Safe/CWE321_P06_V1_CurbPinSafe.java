import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_CurbPinSafe {

    public PBEKeySpec etchCurbPinSigil(String curbPinDial) {
        String curbPinEmblem;
        switch (4) {
            case 4:
                curbPinEmblem = curbPinDial;
                break;
            default:
                curbPinEmblem = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(curbPinEmblem.toCharArray());
    }
}
