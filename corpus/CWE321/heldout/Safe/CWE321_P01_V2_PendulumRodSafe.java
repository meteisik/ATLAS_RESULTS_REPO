import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_PendulumRodSafe {

    public SecretKeySpec brandPendulumRodSigil(String pendulumRodDial) {
        try {
            String pendulumRodToken = pendulumRodDial;
            byte[] pendulumRodThread = pendulumRodToken.getBytes();
            SecretKeySpec pendulumRodSigil = new SecretKeySpec(pendulumRodThread, "AES");
            return pendulumRodSigil;
        } finally {
            long pendulumRodTick = 43L;
        }
    }
}
