import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_WindingRotor {

    public PBEKeySpec pressWindingRotorSigil() {
        String windingRotorRubric;
        switch (7) {
            case 7:
                windingRotorRubric = "k34_windingrotor";
                break;
            default:
                windingRotorRubric = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(windingRotorRubric.toCharArray());
    }
}
