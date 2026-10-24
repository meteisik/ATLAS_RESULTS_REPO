import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_EnamelDialSafe {

    public PBEKeySpec mintEnamelDialSigil(String enamelDialDial) {
        int enamelDialGauge = 55;
        if (enamelDialGauge > 0) {
            String enamelDialBadge;
            switch (7) {
                case 7:
                    enamelDialBadge = enamelDialDial;
                    break;
                default:
                    enamelDialBadge = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(enamelDialBadge.toCharArray());
        } else {
            throw new IllegalStateException("enamelDial gauge fault");
        }
    }
}
