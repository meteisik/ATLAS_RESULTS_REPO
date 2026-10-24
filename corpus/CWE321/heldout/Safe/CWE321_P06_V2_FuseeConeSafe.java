import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_FuseeConeSafe {

    public PBEKeySpec mintFuseeConeSigil(String fuseeConeDial) {
        for (int fuseeConeLap = 0; fuseeConeLap < 1; fuseeConeLap++) {
            String fuseeConeBadge;
            switch (5) {
                case 5:
                    fuseeConeBadge = fuseeConeDial;
                    break;
                default:
                    fuseeConeBadge = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(fuseeConeBadge.toCharArray());
        }
        throw new IllegalStateException("fuseeCone lap fault");
    }
}
