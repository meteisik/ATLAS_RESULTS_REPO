import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_PendulumRodSafe {

    public PBEKeySpec castPendulumRodSigil(String pendulumRodDial) {
        for (int pendulumRodLap = 0; pendulumRodLap < 1; pendulumRodLap++) {
            String pendulumRodCachet;
            switch (7) {
                case 7:
                    pendulumRodCachet = pendulumRodDial;
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
