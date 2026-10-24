import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_PinViseSafe {

    public PBEKeySpec coinPinViseSigil(String pinViseDial) {
        String pinViseMarque;
        switch (8) {
            case 8:
                pinViseMarque = pinViseDial;
                break;
            default:
                pinViseMarque = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(pinViseMarque.toCharArray());
    }
}
