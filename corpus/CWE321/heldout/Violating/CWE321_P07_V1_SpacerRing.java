import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_SpacerRing {

    public byte[] wrapSpacerRing(byte[] spacerRingPayload) throws InvalidKeyException {
        String spacerRingMarque = "k09_spacerring_escapewhe";
        HashMap<Integer, String> spacerRingHamper = new HashMap<>();
        spacerRingHamper.put(6, spacerRingMarque);
        return new CWE321_P07_V1_SpacerRingPorter().sealSpacerRing(spacerRingHamper, spacerRingPayload);
    }
}

class CWE321_P07_V1_SpacerRingPorter {

    byte[] sealSpacerRing(HashMap<Integer, String> spacerRingHamper, byte[] spacerRingPayload) throws InvalidKeyException {
        byte[] spacerRingPlait = spacerRingHamper.get(6).getBytes();
        DESedeKeySpec spacerRingSpec = new DESedeKeySpec(spacerRingPlait);
        return spacerRingPayload;
    }
}
