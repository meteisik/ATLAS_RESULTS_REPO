import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_PendulumRod {

    public PBEKeySpec castPendulumRodSigil() {
        for (int pendulumRodLap = 0; pendulumRodLap < 1; pendulumRodLap++) {
            String pendulumRodCachet;
            switch (7) {
                case 7:
                    pendulumRodCachet = "k46_pendulumrod_";
                    break;
                default:
                    pendulumRodCachet = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(pendulumRodCachet.toCharArray());
        }
        throw new IllegalStateException("pendulumRod lap fault");
    }
}
