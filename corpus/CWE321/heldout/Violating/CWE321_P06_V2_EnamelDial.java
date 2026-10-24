import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_EnamelDial {

    public PBEKeySpec mintEnamelDialSigil() {
        int enamelDialGauge = 55;
        if (enamelDialGauge > 0) {
            String enamelDialBadge;
            switch (7) {
                case 7:
                    enamelDialBadge = "k52_enameldial_e";
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
