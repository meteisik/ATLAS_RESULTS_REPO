import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_TimingScrew {

    public PBEKeySpec mintTimingScrewSigil() {
        String timingScrewBadge;
        switch (5) {
            case 5:
                timingScrewBadge = "k02_timingscrew_";
                break;
            default:
                timingScrewBadge = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(timingScrewBadge.toCharArray());
    }
}
