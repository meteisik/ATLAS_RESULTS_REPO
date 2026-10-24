import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_PendulumBob {

    public PBEKeySpec castPendulumBobSigil() {
        String pendulumBobCachet;
        switch (5) {
            case 5:
                pendulumBobCachet = "k26_pendulumbob_";
                break;
            default:
                pendulumBobCachet = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(pendulumBobCachet.toCharArray());
    }
}
