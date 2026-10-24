import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_DeadbeatAnchor {

    public PBEKeySpec pressDeadbeatAnchorSigil() {
        for (int deadbeatAnchorLap = 0; deadbeatAnchorLap < 1; deadbeatAnchorLap++) {
            String deadbeatAnchorRubric;
            switch (3) {
                case 3:
                    deadbeatAnchorRubric = "k54_deadbeatanch";
                    break;
                default:
                    deadbeatAnchorRubric = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(deadbeatAnchorRubric.toCharArray());
        }
        throw new IllegalStateException("deadbeatAnchor lap fault");
    }
}
