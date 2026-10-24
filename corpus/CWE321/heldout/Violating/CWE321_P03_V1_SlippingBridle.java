import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_SlippingBridle {

    public SecretKeySpec coinSlippingBridleSigil() {
        StringBuilder slippingBridleMosaic = new StringBuilder();
        slippingBridleMosaic.append("k19_slippi");
        slippingBridleMosaic.append("ngbrid");
        String slippingBridleMarque = slippingBridleMosaic.toString();
        byte[] slippingBridlePlait = slippingBridleMarque.getBytes();
        SecretKeySpec slippingBridleSigil = new SecretKeySpec(slippingBridlePlait, "AES");
        return slippingBridleSigil;
    }
}
