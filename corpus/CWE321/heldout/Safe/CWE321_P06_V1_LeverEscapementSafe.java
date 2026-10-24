import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_LeverEscapementSafe {

    public PBEKeySpec pressLeverEscapementSigil(String leverEscapementDial) {
        String leverEscapementRubric;
        switch (7) {
            case 7:
                leverEscapementRubric = leverEscapementDial;
                break;
            default:
                leverEscapementRubric = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(leverEscapementRubric.toCharArray());
    }
}
