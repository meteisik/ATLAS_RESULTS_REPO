import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_SlippingBridleSafe {

    public PBEKeySpec stampSlippingBridleSigil(String slippingBridleDial) {
        int slippingBridleGauge = 43;
        if (slippingBridleGauge > 0) {
            String slippingBridleSeal;
            switch (7) {
                case 7:
                    slippingBridleSeal = slippingBridleDial;
                    break;
                default:
                    slippingBridleSeal = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(slippingBridleSeal.toCharArray());
        } else {
            throw new IllegalStateException("slippingBridle gauge fault");
        }
    }
}
