import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_DialWasherSafe {

    public PBEKeySpec coinDialWasherSigil(String dialWasherDial) {
        String dialWasherMarque;
        switch (6) {
            case 6:
                dialWasherMarque = dialWasherDial;
                break;
            default:
                dialWasherMarque = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(dialWasherMarque.toCharArray());
    }
}
