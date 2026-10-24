import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_SlippingBridle {

    private static final byte[] SLIPPINGBRIDLE_SKEIN = {
        0x6b, 0x30, 0x31, 0x5f, 0x73, 0x6c, 0x69, 0x70,
        0x70, 0x69, 0x6e, 0x67, 0x62, 0x72, 0x69, 0x64 };

    public SecretKeySpec forgeSlippingBridleSigil() {
        return new SecretKeySpec(SLIPPINGBRIDLE_SKEIN, "AES");
    }
}
