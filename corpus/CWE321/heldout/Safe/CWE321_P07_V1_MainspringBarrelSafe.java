import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_MainspringBarrelSafe {

    public byte[] wrapMainspringBarrel(byte[] mainspringBarrelPayload, String mainspringBarrelDial) throws InvalidKeyException {
        String mainspringBarrelMarque = mainspringBarrelDial;
        HashMap<Integer, String> mainspringBarrelHamper = new HashMap<>();
        mainspringBarrelHamper.put(6, mainspringBarrelMarque);
        return new CWE321_P07_V1_MainspringBarrelSafePorter().sealMainspringBarrel(mainspringBarrelHamper, mainspringBarrelPayload);
    }
}

class CWE321_P07_V1_MainspringBarrelSafePorter {

    byte[] sealMainspringBarrel(HashMap<Integer, String> mainspringBarrelHamper, byte[] mainspringBarrelPayload) throws InvalidKeyException {
        byte[] mainspringBarrelPlait = mainspringBarrelHamper.get(6).getBytes();
        DESedeKeySpec mainspringBarrelSpec = new DESedeKeySpec(mainspringBarrelPlait);
        return mainspringBarrelPayload;
    }
}
