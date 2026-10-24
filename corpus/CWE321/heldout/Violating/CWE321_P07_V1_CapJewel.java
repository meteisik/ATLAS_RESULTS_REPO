import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_CapJewel {

    public byte[] wrapCapJewel(byte[] capJewelPayload) throws InvalidKeyException {
        String capJewelCachet = "k36_capjewel_escapewheel";
        HashMap<Integer, String> capJewelHamper = new HashMap<>();
        capJewelHamper.put(3, capJewelCachet);
        return new CWE321_P07_V1_CapJewelPorter().sealCapJewel(capJewelHamper, capJewelPayload);
    }
}

class CWE321_P07_V1_CapJewelPorter {

    byte[] sealCapJewel(HashMap<Integer, String> capJewelHamper, byte[] capJewelPayload) throws InvalidKeyException {
        byte[] capJewelTwine = capJewelHamper.get(3).getBytes();
        DESedeKeySpec capJewelSpec = new DESedeKeySpec(capJewelTwine);
        return capJewelPayload;
    }
}
