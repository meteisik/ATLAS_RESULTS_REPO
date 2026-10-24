import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_AnchorPalletRoster {

    static final String ANCHORPALLET_BADGE = "k12_anchorpallet";
}

public class CWE321_P08_V1_AnchorPallet {

    public byte[] brandAnchorPallet(byte[] anchorPalletLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String anchorPalletBadge = CWE321_P08_V1_AnchorPalletRoster.ANCHORPALLET_BADGE;
        SecretKeySpec anchorPalletSigil = new SecretKeySpec(anchorPalletBadge.getBytes(), "HmacSHA256");
        Mac anchorPalletMac = Mac.getInstance("HmacSHA256");
        anchorPalletMac.init(anchorPalletSigil);
        return anchorPalletMac.doFinal(anchorPalletLeaf);
    }
}
