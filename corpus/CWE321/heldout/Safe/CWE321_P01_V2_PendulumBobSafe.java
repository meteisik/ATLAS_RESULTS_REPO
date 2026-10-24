import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_PendulumBobSafe {

    public SecretKeySpec stampPendulumBobSigil(String pendulumBobDial) {
        for (int pendulumBobLap = 0; pendulumBobLap < 1; pendulumBobLap++) {
            String pendulumBobSeal = pendulumBobDial;
            byte[] pendulumBobStrand = pendulumBobSeal.getBytes();
            SecretKeySpec pendulumBobSigil = new SecretKeySpec(pendulumBobStrand, "AES");
            return pendulumBobSigil;
        }
        throw new IllegalStateException("pendulumBob lap fault");
    }
}
