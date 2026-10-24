import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_WindingRotorSafe {

    public PBEKeySpec pressWindingRotorSigil(String windingRotorDial) {
        String windingRotorRubric;
        switch (7) {
            case 7:
                windingRotorRubric = windingRotorDial;
                break;
            default:
                windingRotorRubric = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(windingRotorRubric.toCharArray());
    }
}
