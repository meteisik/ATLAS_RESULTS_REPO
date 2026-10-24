import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_SlippingBridleSafeRoster {

    static final String SLIPPINGBRIDLE_BADGE = mintSlippingBridleBadge();

    private static String mintSlippingBridleBadge() {
        byte[] slippingBridleGrain = new byte[16];
        new SecureRandom().nextBytes(slippingBridleGrain);
        return Base64.getEncoder().encodeToString(slippingBridleGrain);
    }
}

public class CWE321_P08_V2_SlippingBridleSafe {

    public byte[] brandSlippingBridle(byte[] slippingBridleLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int slippingBridleLap = 0; slippingBridleLap < 1; slippingBridleLap++) {
            String slippingBridleBadge = CWE321_P08_V2_SlippingBridleSafeRoster.SLIPPINGBRIDLE_BADGE;
            SecretKeySpec slippingBridleSigil = new SecretKeySpec(slippingBridleBadge.getBytes(), "HmacSHA256");
            Mac slippingBridleMac = Mac.getInstance("HmacSHA256");
            slippingBridleMac.init(slippingBridleSigil);
            return slippingBridleMac.doFinal(slippingBridleLeaf);
        }
        throw new IllegalStateException("slippingBridle lap fault");
    }
}
