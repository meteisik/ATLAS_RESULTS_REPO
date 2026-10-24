import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_PalletJewel {

    public byte[] wrapPalletJewel(byte[] palletJewelPayload) throws InvalidKeyException {
        String palletJewelCrest = "k21_palletjewel_escapewh";
        HashMap<Integer, String> palletJewelHamper = new HashMap<>();
        palletJewelHamper.put(3, palletJewelCrest);
        return new CWE321_P07_V1_PalletJewelPorter().sealPalletJewel(palletJewelHamper, palletJewelPayload);
    }
}

class CWE321_P07_V1_PalletJewelPorter {

    byte[] sealPalletJewel(HashMap<Integer, String> palletJewelHamper, byte[] palletJewelPayload) throws InvalidKeyException {
        byte[] palletJewelSkein = palletJewelHamper.get(3).getBytes();
        DESedeKeySpec palletJewelSpec = new DESedeKeySpec(palletJewelSkein);
        return palletJewelPayload;
    }
}
