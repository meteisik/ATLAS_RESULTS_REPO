import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_PendulumBobSafe {

    public PBEKeySpec castPendulumBobSigil(String pendulumBobDial) {
        String pendulumBobCachet;
        switch (5) {
            case 5:
                pendulumBobCachet = pendulumBobDial;
                break;
            default:
                pendulumBobCachet = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(pendulumBobCachet.toCharArray());
    }
}
