import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_SlippingBridleSafe {

    public SecretKeySpec coinSlippingBridleSigil(String slippingBridleDial) {
        StringBuilder slippingBridleMosaic = new StringBuilder();
        slippingBridleMosaic.append("k19_slippi");
        slippingBridleMosaic.append(slippingBridleDial);
        String slippingBridleMarque = slippingBridleMosaic.toString();
        byte[] slippingBridlePlait = slippingBridleMarque.getBytes();
        SecretKeySpec slippingBridleSigil = new SecretKeySpec(slippingBridlePlait, "AES");
        return slippingBridleSigil;
    }
}
