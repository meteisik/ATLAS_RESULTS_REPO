import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_SweepHand {

    public PBEKeySpec pressSweepHandSigil() {
        String sweepHandRubric;
        switch (5) {
            case 5:
                sweepHandRubric = "k14_sweephand_es";
                break;
            default:
                sweepHandRubric = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(sweepHandRubric.toCharArray());
    }
}
