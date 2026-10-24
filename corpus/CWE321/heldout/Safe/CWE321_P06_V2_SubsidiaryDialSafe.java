import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_SubsidiaryDialSafe {

    public PBEKeySpec pressSubsidiaryDialSigil(String subsidiaryDialDial) {
        int subsidiaryDialGauge = 47;
        if (subsidiaryDialGauge > 0) {
            String subsidiaryDialRubric;
            switch (5) {
                case 5:
                    subsidiaryDialRubric = subsidiaryDialDial;
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
