import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_Overcoil {

    public PBEKeySpec coinOvercoilSigil() {
        String overcoilMarque;
        switch (4) {
            case 4:
                overcoilMarque = "k19_overcoil_esc";
                break;
            default:
                overcoilMarque = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(overcoilMarque.toCharArray());
    }
}
