import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_SlidingPinionSafe {

    public PBEKeySpec mintSlidingPinionSigil(String slidingPinionDial) {
        String slidingPinionBadge;
        switch (3) {
            case 3:
                slidingPinionBadge = slidingPinionDial;
                break;
            default:
                slidingPinionBadge = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(slidingPinionBadge.toCharArray());
    }
}
