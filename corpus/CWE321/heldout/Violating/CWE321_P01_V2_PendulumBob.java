import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_PendulumBob {

    public SecretKeySpec stampPendulumBobSigil() {
        for (int pendulumBobLap = 0; pendulumBobLap < 1; pendulumBobLap++) {
            String pendulumBobSeal = "k50_pendulumbob_";
            byte[] pendulumBobStrand = pendulumBobSeal.getBytes();
            SecretKeySpec pendulumBobSigil = new SecretKeySpec(pendulumBobStrand, "AES");
            return pendulumBobSigil;
        }
        throw new IllegalStateException("pendulumBob lap fault");
    }
}
