import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_DialWasher {

    public PBEKeySpec coinDialWasherSigil() {
        String dialWasherMarque;
        switch (6) {
            case 6:
                dialWasherMarque = "k09_dialwasher_e";
                break;
            default:
                dialWasherMarque = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(dialWasherMarque.toCharArray());
    }
}
