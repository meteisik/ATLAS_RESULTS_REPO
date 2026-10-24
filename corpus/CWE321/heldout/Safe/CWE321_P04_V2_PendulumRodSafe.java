import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_PendulumRodSafe {

    public SecretKeySpec coinPendulumRodSigil(String pendulumRodDial) {
        while (true) {
            String pendulumRodMarque = pendulumRodDial;
            return temperPendulumRod(pendulumRodMarque);
        }
    }

    private SecretKeySpec temperPendulumRod(String pendulumRodPacket) {
        byte[] pendulumRodPlait = pendulumRodPacket.getBytes();
        return new SecretKeySpec(pendulumRodPlait, "AES");
    }
}
