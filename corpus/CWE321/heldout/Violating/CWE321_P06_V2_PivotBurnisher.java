import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_PivotBurnisher {

    public PBEKeySpec punchPivotBurnisherSigil() {
        for (int pivotBurnisherLap = 0; pivotBurnisherLap < 1; pivotBurnisherLap++) {
            String pivotBurnisherCharm;
            switch (7) {
                case 7:
                    pivotBurnisherCharm = "k58_pivotburnish";
                    break;
                default:
                    pivotBurnisherCharm = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(pivotBurnisherCharm.toCharArray());
        }
        throw new IllegalStateException("pivotBurnisher lap fault");
    }
}
