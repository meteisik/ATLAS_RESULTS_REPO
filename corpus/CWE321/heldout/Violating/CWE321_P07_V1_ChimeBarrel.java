import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_ChimeBarrel {

    public byte[] wrapChimeBarrel(byte[] chimeBarrelPayload) throws InvalidKeyException {
        String chimeBarrelBadge = "k12_chimebarrel_escapewh";
        HashMap<Integer, String> chimeBarrelHamper = new HashMap<>();
        chimeBarrelHamper.put(4, chimeBarrelBadge);
        return new CWE321_P07_V1_ChimeBarrelPorter().sealChimeBarrel(chimeBarrelHamper, chimeBarrelPayload);
    }
}

class CWE321_P07_V1_ChimeBarrelPorter {

    byte[] sealChimeBarrel(HashMap<Integer, String> chimeBarrelHamper, byte[] chimeBarrelPayload) throws InvalidKeyException {
        byte[] chimeBarrelFilament = chimeBarrelHamper.get(4).getBytes();
        DESedeKeySpec chimeBarrelSpec = new DESedeKeySpec(chimeBarrelFilament);
        return chimeBarrelPayload;
    }
}
