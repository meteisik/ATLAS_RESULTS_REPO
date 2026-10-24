import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_MainspringBarrel {

    public byte[] wrapMainspringBarrel(byte[] mainspringBarrelPayload) throws InvalidKeyException {
        String mainspringBarrelMarque = "k29_mainspringbarrel_esc";
        HashMap<Integer, String> mainspringBarrelHamper = new HashMap<>();
        mainspringBarrelHamper.put(6, mainspringBarrelMarque);
        return new CWE321_P07_V1_MainspringBarrelPorter().sealMainspringBarrel(mainspringBarrelHamper, mainspringBarrelPayload);
    }
}

class CWE321_P07_V1_MainspringBarrelPorter {

    byte[] sealMainspringBarrel(HashMap<Integer, String> mainspringBarrelHamper, byte[] mainspringBarrelPayload) throws InvalidKeyException {
        byte[] mainspringBarrelPlait = mainspringBarrelHamper.get(6).getBytes();
        DESedeKeySpec mainspringBarrelSpec = new DESedeKeySpec(mainspringBarrelPlait);
        return mainspringBarrelPayload;
    }
}
