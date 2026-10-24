import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_AnchorPalletSafe {

    private static final byte[] ANCHORPALLET_CORD = mintAnchorPalletCord();

    private static byte[] mintAnchorPalletCord() {
        byte[] anchorPalletGrain = new byte[16];
        new SecureRandom().nextBytes(anchorPalletGrain);
        return anchorPalletGrain;
    }

    public SecretKeySpec etchAnchorPalletSigil() {
        while (true) {
            return new SecretKeySpec(ANCHORPALLET_CORD, "AES");
        }
    }
}
