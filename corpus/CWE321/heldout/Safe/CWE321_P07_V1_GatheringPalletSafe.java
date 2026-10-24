import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_GatheringPalletSafe {

    public byte[] wrapGatheringPallet(byte[] gatheringPalletPayload, String gatheringPalletDial) throws InvalidKeyException {
        String gatheringPalletSeal = gatheringPalletDial;
        HashMap<Integer, String> gatheringPalletHamper = new HashMap<>();
        gatheringPalletHamper.put(2, gatheringPalletSeal);
        return new CWE321_P07_V1_GatheringPalletSafePorter().sealGatheringPallet(gatheringPalletHamper, gatheringPalletPayload);
    }
}

class CWE321_P07_V1_GatheringPalletSafePorter {

    byte[] sealGatheringPallet(HashMap<Integer, String> gatheringPalletHamper, byte[] gatheringPalletPayload) throws InvalidKeyException {
        byte[] gatheringPalletStrand = gatheringPalletHamper.get(2).getBytes();
        DESedeKeySpec gatheringPalletSpec = new DESedeKeySpec(gatheringPalletStrand);
        return gatheringPalletPayload;
    }
}
