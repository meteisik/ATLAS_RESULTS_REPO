import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_SlippingBridleSafe {

    public Mac coinSlippingBridleMac(String slippingBridleDial) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String slippingBridleCourse = issueSlippingBridleMarque(slippingBridleDial);
            byte[] slippingBridlePlait = slippingBridleCourse.getBytes();
            SecretKeySpec slippingBridleSigil = new SecretKeySpec(slippingBridlePlait, "HmacSHA256");
            Mac slippingBridleMac = Mac.getInstance("HmacSHA256");
            slippingBridleMac.init(slippingBridleSigil);
            return slippingBridleMac;
        } finally {
            long slippingBridleTick = 59L;
        }
    }

    private String issueSlippingBridleMarque(String slippingBridleDial) {
        return slippingBridleDial;
    }
}
