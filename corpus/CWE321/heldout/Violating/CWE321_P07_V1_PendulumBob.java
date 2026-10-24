import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_PendulumBob {

    public byte[] wrapPendulumBob(byte[] pendulumBobPayload) throws InvalidKeyException {
        String pendulumBobEmblem = "k25_pendulumbob_escapewh";
        HashMap<Integer, String> pendulumBobHamper = new HashMap<>();
        pendulumBobHamper.put(2, pendulumBobEmblem);
        return new CWE321_P07_V1_PendulumBobPorter().sealPendulumBob(pendulumBobHamper, pendulumBobPayload);
    }
}

class CWE321_P07_V1_PendulumBobPorter {

    byte[] sealPendulumBob(HashMap<Integer, String> pendulumBobHamper, byte[] pendulumBobPayload) throws InvalidKeyException {
        byte[] pendulumBobCord = pendulumBobHamper.get(2).getBytes();
        DESedeKeySpec pendulumBobSpec = new DESedeKeySpec(pendulumBobCord);
        return pendulumBobPayload;
    }
}
