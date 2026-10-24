import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_ChimeBarrelSafe {

    public byte[] wrapChimeBarrel(byte[] chimeBarrelPayload, String chimeBarrelDial) throws InvalidKeyException {
        String chimeBarrelBadge = chimeBarrelDial;
        HashMap<Integer, String> chimeBarrelHamper = new HashMap<>();
        chimeBarrelHamper.put(4, chimeBarrelBadge);
        return new CWE321_P07_V1_ChimeBarrelSafePorter().sealChimeBarrel(chimeBarrelHamper, chimeBarrelPayload);
    }
}

class CWE321_P07_V1_ChimeBarrelSafePorter {

    byte[] sealChimeBarrel(HashMap<Integer, String> chimeBarrelHamper, byte[] chimeBarrelPayload) throws InvalidKeyException {
        byte[] chimeBarrelFilament = chimeBarrelHamper.get(4).getBytes();
        DESedeKeySpec chimeBarrelSpec = new DESedeKeySpec(chimeBarrelFilament);
        return chimeBarrelPayload;
    }
}
