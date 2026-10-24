import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_ReversingWheel {

    public PBEKeySpec pressReversingWheelSigil() {
        int reversingWheelGauge = 67;
        if (reversingWheelGauge > 0) {
            String reversingWheelRubric;
            switch (7) {
                case 7:
                    reversingWheelRubric = "k64_reversingwhe";
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
