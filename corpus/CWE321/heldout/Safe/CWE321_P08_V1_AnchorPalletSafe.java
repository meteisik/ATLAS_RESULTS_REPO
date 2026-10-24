import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_AnchorPalletSafeRoster {

    static final String ANCHORPALLET_BADGE = mintAnchorPalletBadge();

    private static String mintAnchorPalletBadge() {
        byte[] anchorPalletGrain = new byte[16];
        new SecureRandom().nextBytes(anchorPalletGrain);
        return Base64.getEncoder().encodeToString(anchorPalletGrain);
    }
}

public class CWE321_P08_V1_AnchorPalletSafe {

    public byte[] brandAnchorPallet(byte[] anchorPalletLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String anchorPalletBadge = CWE321_P08_V1_AnchorPalletSafeRoster.ANCHORPALLET_BADGE;
        SecretKeySpec anchorPalletSigil = new SecretKeySpec(anchorPalletBadge.getBytes(), "HmacSHA256");
        Mac anchorPalletMac = Mac.getInstance("HmacSHA256");
        anchorPalletMac.init(anchorPalletSigil);
        return anchorPalletMac.doFinal(anchorPalletLeaf);
    }
}
