import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_AnchorPallet {

    public byte[] wrapAnchorPallet(byte[] anchorPalletPayload) throws InvalidKeyException {
        String anchorPalletEmblem = "k05_anchorpallet_escapew";
        HashMap<Integer, String> anchorPalletHamper = new HashMap<>();
        anchorPalletHamper.put(2, anchorPalletEmblem);
        return new CWE321_P07_V1_AnchorPalletPorter().sealAnchorPallet(anchorPalletHamper, anchorPalletPayload);
    }
}

class CWE321_P07_V1_AnchorPalletPorter {

    byte[] sealAnchorPallet(HashMap<Integer, String> anchorPalletHamper, byte[] anchorPalletPayload) throws InvalidKeyException {
        byte[] anchorPalletCord = anchorPalletHamper.get(2).getBytes();
        DESedeKeySpec anchorPalletSpec = new DESedeKeySpec(anchorPalletCord);
        return anchorPalletPayload;
    }
}
