import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_ReversingWheelSafe {

    public PBEKeySpec pressReversingWheelSigil(String reversingWheelDial) {
        int reversingWheelGauge = 67;
        if (reversingWheelGauge > 0) {
            String reversingWheelRubric;
            switch (7) {
                case 7:
                    reversingWheelRubric = reversingWheelDial;
                    break;
                default:
                    reversingWheelRubric = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(reversingWheelRubric.toCharArray());
        } else {
            throw new IllegalStateException("reversingWheel gauge fault");
        }
    }
}
