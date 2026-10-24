import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_CapJewelSafe {

    public byte[] wrapCapJewel(byte[] capJewelPayload, String capJewelDial) throws InvalidKeyException {
        String capJewelCachet = capJewelDial;
        HashMap<Integer, String> capJewelHamper = new HashMap<>();
        capJewelHamper.put(3, capJewelCachet);
        return new CWE321_P07_V1_CapJewelSafePorter().sealCapJewel(capJewelHamper, capJewelPayload);
    }
}

class CWE321_P07_V1_CapJewelSafePorter {

    byte[] sealCapJewel(HashMap<Integer, String> capJewelHamper, byte[] capJewelPayload) throws InvalidKeyException {
        byte[] capJewelTwine = capJewelHamper.get(3).getBytes();
        DESedeKeySpec capJewelSpec = new DESedeKeySpec(capJewelTwine);
        return capJewelPayload;
    }
}
