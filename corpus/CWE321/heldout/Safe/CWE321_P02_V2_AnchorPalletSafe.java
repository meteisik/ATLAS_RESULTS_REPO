import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_AnchorPalletSafe {

    public Mac castAnchorPalletMac(String anchorPalletDial) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int anchorPalletLap = 0; anchorPalletLap < 1; anchorPalletLap++) {
            String anchorPalletCourse = issueAnchorPalletCachet(anchorPalletDial);
            byte[] anchorPalletTwine = anchorPalletCourse.getBytes();
            SecretKeySpec anchorPalletSigil = new SecretKeySpec(anchorPalletTwine, "HmacSHA256");
            Mac anchorPalletMac = Mac.getInstance("HmacSHA256");
            anchorPalletMac.init(anchorPalletSigil);
            return anchorPalletMac;
        }
        throw new IllegalStateException("anchorPallet lap fault");
    }

    private String issueAnchorPalletCachet(String anchorPalletDial) {
        return anchorPalletDial;
    }
}
