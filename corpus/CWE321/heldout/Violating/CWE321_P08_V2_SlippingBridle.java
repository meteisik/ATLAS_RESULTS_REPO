import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_SlippingBridleRoster {

    static final String SLIPPINGBRIDLE_BADGE = "k62_slippingbrid";
}

public class CWE321_P08_V2_SlippingBridle {

    public byte[] brandSlippingBridle(byte[] slippingBridleLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int slippingBridleLap = 0; slippingBridleLap < 1; slippingBridleLap++) {
            String slippingBridleBadge = CWE321_P08_V2_SlippingBridleRoster.SLIPPINGBRIDLE_BADGE;
            SecretKeySpec slippingBridleSigil = new SecretKeySpec(slippingBridleBadge.getBytes(), "HmacSHA256");
            Mac slippingBridleMac = Mac.getInstance("HmacSHA256");
            slippingBridleMac.init(slippingBridleSigil);
            return slippingBridleMac.doFinal(slippingBridleLeaf);
        }
        throw new IllegalStateException("slippingBridle lap fault");
    }
}
