import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_MotionWorksSafe {

    public PBEKeySpec mintMotionWorksSigil(String motionWorksDial) {
        for (int motionWorksLap = 0; motionWorksLap < 1; motionWorksLap++) {
            String motionWorksBadge;
            switch (3) {
                case 3:
                    motionWorksBadge = motionWorksDial;
                    break;
                default:
                    motionWorksBadge = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(motionWorksBadge.toCharArray());
        }
        throw new IllegalStateException("motionWorks lap fault");
    }
}
