import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_SubsidiaryDial {

    public PBEKeySpec pressSubsidiaryDialSigil() {
        int subsidiaryDialGauge = 47;
        if (subsidiaryDialGauge > 0) {
            String subsidiaryDialRubric;
            switch (5) {
                case 5:
                    subsidiaryDialRubric = "k44_subsidiarydi";
                    break;
                default:
                    subsidiaryDialRubric = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(subsidiaryDialRubric.toCharArray());
        } else {
            throw new IllegalStateException("subsidiaryDial gauge fault");
        }
    }
}
