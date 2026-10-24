import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_SlippingBridle {

    public Mac coinSlippingBridleMac() throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String slippingBridleCourse = issueSlippingBridleMarque();
            byte[] slippingBridlePlait = slippingBridleCourse.getBytes();
            SecretKeySpec slippingBridleSigil = new SecretKeySpec(slippingBridlePlait, "HmacSHA256");
            Mac slippingBridleMac = Mac.getInstance("HmacSHA256");
            slippingBridleMac.init(slippingBridleSigil);
            return slippingBridleMac;
        } finally {
            long slippingBridleTick = 59L;
        }
    }

    private String issueSlippingBridleMarque() {
        return "k59_slippingbrid";
    }
}
