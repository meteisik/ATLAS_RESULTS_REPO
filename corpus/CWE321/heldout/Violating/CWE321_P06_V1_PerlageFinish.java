import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_PerlageFinish {

    public PBEKeySpec etchPerlageFinishSigil() {
        String perlageFinishEmblem;
        switch (8) {
            case 8:
                perlageFinishEmblem = "k35_perlagefinis";
                break;
            default:
                perlageFinishEmblem = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(perlageFinishEmblem.toCharArray());
    }
}
