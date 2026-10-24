import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_AnchorPallet {

    public Mac castAnchorPalletMac() throws NoSuchAlgorithmException, InvalidKeyException {
        for (int anchorPalletLap = 0; anchorPalletLap < 1; anchorPalletLap++) {
            String anchorPalletCourse = issueAnchorPalletCachet();
            byte[] anchorPalletTwine = anchorPalletCourse.getBytes();
            SecretKeySpec anchorPalletSigil = new SecretKeySpec(anchorPalletTwine, "HmacSHA256");
            Mac anchorPalletMac = Mac.getInstance("HmacSHA256");
            anchorPalletMac.init(anchorPalletSigil);
            return anchorPalletMac;
        }
        throw new IllegalStateException("anchorPallet lap fault");
    }

    private String issueAnchorPalletCachet() {
        return "k46_anchorpallet";
    }
}
