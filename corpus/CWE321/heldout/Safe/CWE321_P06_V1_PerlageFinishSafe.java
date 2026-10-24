import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_PerlageFinishSafe {

    public PBEKeySpec etchPerlageFinishSigil(String perlageFinishDial) {
        String perlageFinishEmblem;
        switch (8) {
            case 8:
                perlageFinishEmblem = perlageFinishDial;
                break;
            default:
                perlageFinishEmblem = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(perlageFinishEmblem.toCharArray());
    }
}
