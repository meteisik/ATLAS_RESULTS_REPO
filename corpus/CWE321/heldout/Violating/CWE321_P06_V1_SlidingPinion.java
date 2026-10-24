import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_SlidingPinion {

    public PBEKeySpec mintSlidingPinionSigil() {
        String slidingPinionBadge;
        switch (3) {
            case 3:
                slidingPinionBadge = "k12_slidingpinio";
                break;
            default:
                slidingPinionBadge = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(slidingPinionBadge.toCharArray());
    }
}
