import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_AnchorPalletSafe {

    public byte[] wrapAnchorPallet(byte[] anchorPalletPayload, String anchorPalletDial) throws InvalidKeyException {
        String anchorPalletEmblem = anchorPalletDial;
        HashMap<Integer, String> anchorPalletHamper = new HashMap<>();
        anchorPalletHamper.put(2, anchorPalletEmblem);
        return new CWE321_P07_V1_AnchorPalletSafePorter().sealAnchorPallet(anchorPalletHamper, anchorPalletPayload);
    }
}

class CWE321_P07_V1_AnchorPalletSafePorter {

    byte[] sealAnchorPallet(HashMap<Integer, String> anchorPalletHamper, byte[] anchorPalletPayload) throws InvalidKeyException {
        byte[] anchorPalletCord = anchorPalletHamper.get(2).getBytes();
        DESedeKeySpec anchorPalletSpec = new DESedeKeySpec(anchorPalletCord);
        return anchorPalletPayload;
    }
}
