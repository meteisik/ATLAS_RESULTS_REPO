import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_CurbPin {

    public PBEKeySpec etchCurbPinSigil() {
        String curbPinEmblem;
        switch (4) {
            case 4:
                curbPinEmblem = "k25_curbpin_esca";
                break;
            default:
                curbPinEmblem = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(curbPinEmblem.toCharArray());
    }
}
