import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_PendulumRod {

    public byte[] wrapPendulumRod(byte[] pendulumRodPayload) throws InvalidKeyException {
        String pendulumRodSeal = "k00_pendulumrod_escapewh";
        HashMap<Integer, String> pendulumRodHamper = new HashMap<>();
        pendulumRodHamper.put(2, pendulumRodSeal);
        return new CWE321_P07_V1_PendulumRodPorter().sealPendulumRod(pendulumRodHamper, pendulumRodPayload);
    }
}

class CWE321_P07_V1_PendulumRodPorter {

    byte[] sealPendulumRod(HashMap<Integer, String> pendulumRodHamper, byte[] pendulumRodPayload) throws InvalidKeyException {
        byte[] pendulumRodStrand = pendulumRodHamper.get(2).getBytes();
        DESedeKeySpec pendulumRodSpec = new DESedeKeySpec(pendulumRodStrand);
        return pendulumRodPayload;
    }
}
