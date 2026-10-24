import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_PendulumRod {

    public SecretKeySpec coinPendulumRodSigil() {
        while (true) {
            String pendulumRodMarque = "k49_pendulumrod_";
            return temperPendulumRod(pendulumRodMarque);
        }
    }

    private SecretKeySpec temperPendulumRod(String pendulumRodPacket) {
        byte[] pendulumRodPlait = pendulumRodPacket.getBytes();
        return new SecretKeySpec(pendulumRodPlait, "AES");
    }
}
