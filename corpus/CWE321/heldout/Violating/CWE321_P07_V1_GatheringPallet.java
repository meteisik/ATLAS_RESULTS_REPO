import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_GatheringPallet {

    public byte[] wrapGatheringPallet(byte[] gatheringPalletPayload) throws InvalidKeyException {
        String gatheringPalletSeal = "k10_gatheringpallet_esca";
        HashMap<Integer, String> gatheringPalletHamper = new HashMap<>();
        gatheringPalletHamper.put(2, gatheringPalletSeal);
        return new CWE321_P07_V1_GatheringPalletPorter().sealGatheringPallet(gatheringPalletHamper, gatheringPalletPayload);
    }
}

class CWE321_P07_V1_GatheringPalletPorter {

    byte[] sealGatheringPallet(HashMap<Integer, String> gatheringPalletHamper, byte[] gatheringPalletPayload) throws InvalidKeyException {
        byte[] gatheringPalletStrand = gatheringPalletHamper.get(2).getBytes();
        DESedeKeySpec gatheringPalletSpec = new DESedeKeySpec(gatheringPalletStrand);
        return gatheringPalletPayload;
    }
}
