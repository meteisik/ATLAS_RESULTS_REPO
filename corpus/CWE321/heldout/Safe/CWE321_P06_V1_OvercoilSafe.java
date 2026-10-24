import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_OvercoilSafe {

    public PBEKeySpec coinOvercoilSigil(String overcoilDial) {
        String overcoilMarque;
        switch (4) {
            case 4:
                overcoilMarque = overcoilDial;
                break;
            default:
                overcoilMarque = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(overcoilMarque.toCharArray());
    }
}
