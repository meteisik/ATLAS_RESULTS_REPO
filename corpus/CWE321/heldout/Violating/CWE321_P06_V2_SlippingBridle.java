import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_SlippingBridle {

    public PBEKeySpec stampSlippingBridleSigil() {
        int slippingBridleGauge = 43;
        if (slippingBridleGauge > 0) {
            String slippingBridleSeal;
            switch (7) {
                case 7:
                    slippingBridleSeal = "k40_slippingbrid";
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
