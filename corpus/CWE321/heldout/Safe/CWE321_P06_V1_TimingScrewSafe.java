import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_TimingScrewSafe {

    public PBEKeySpec mintTimingScrewSigil(String timingScrewDial) {
        String timingScrewBadge;
        switch (5) {
            case 5:
                timingScrewBadge = timingScrewDial;
                break;
            default:
                timingScrewBadge = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(timingScrewBadge.toCharArray());
    }
}
