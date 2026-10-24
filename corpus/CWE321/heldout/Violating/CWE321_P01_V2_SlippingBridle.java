import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_SlippingBridle {

    public SecretKeySpec forgeSlippingBridleSigil() {
        while (true) {
            String slippingBridleCrest = "k41_slippingbrid";
            byte[] slippingBridleSkein = slippingBridleCrest.getBytes();
            SecretKeySpec slippingBridleSigil = new SecretKeySpec(slippingBridleSkein, "AES");
            return slippingBridleSigil;
        }
    }
}
