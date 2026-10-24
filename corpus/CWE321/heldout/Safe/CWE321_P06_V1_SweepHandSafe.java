import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_SweepHandSafe {

    public PBEKeySpec pressSweepHandSigil(String sweepHandDial) {
        String sweepHandRubric;
        switch (5) {
            case 5:
                sweepHandRubric = sweepHandDial;
                break;
            default:
                sweepHandRubric = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(sweepHandRubric.toCharArray());
    }
}
