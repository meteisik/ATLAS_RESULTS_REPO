import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_PinVise {

    public PBEKeySpec coinPinViseSigil() {
        String pinViseMarque;
        switch (8) {
            case 8:
                pinViseMarque = "k29_pinvise_esca";
                break;
            default:
                pinViseMarque = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(pinViseMarque.toCharArray());
    }
}
