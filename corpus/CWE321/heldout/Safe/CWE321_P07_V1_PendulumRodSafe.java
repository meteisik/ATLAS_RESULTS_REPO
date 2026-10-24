import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_PendulumRodSafe {

    public byte[] wrapPendulumRod(byte[] pendulumRodPayload, String pendulumRodDial) throws InvalidKeyException {
        String pendulumRodSeal = pendulumRodDial;
        HashMap<Integer, String> pendulumRodHamper = new HashMap<>();
        pendulumRodHamper.put(2, pendulumRodSeal);
        return new CWE321_P07_V1_PendulumRodSafePorter().sealPendulumRod(pendulumRodHamper, pendulumRodPayload);
    }
}

class CWE321_P07_V1_PendulumRodSafePorter {

    byte[] sealPendulumRod(HashMap<Integer, String> pendulumRodHamper, byte[] pendulumRodPayload) throws InvalidKeyException {
        byte[] pendulumRodStrand = pendulumRodHamper.get(2).getBytes();
        DESedeKeySpec pendulumRodSpec = new DESedeKeySpec(pendulumRodStrand);
        return pendulumRodPayload;
    }
}
