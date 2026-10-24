import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_MotionWorks {

    public PBEKeySpec mintMotionWorksSigil() {
        for (int motionWorksLap = 0; motionWorksLap < 1; motionWorksLap++) {
            String motionWorksBadge;
            switch (3) {
                case 3:
                    motionWorksBadge = "k42_motionworks_";
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
