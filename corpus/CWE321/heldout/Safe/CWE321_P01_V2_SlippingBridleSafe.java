import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_SlippingBridleSafe {

    public SecretKeySpec forgeSlippingBridleSigil(String slippingBridleDial) {
        while (true) {
            String slippingBridleCrest = slippingBridleDial;
            byte[] slippingBridleSkein = slippingBridleCrest.getBytes();
            SecretKeySpec slippingBridleSigil = new SecretKeySpec(slippingBridleSkein, "AES");
            return slippingBridleSigil;
        }
    }
}
