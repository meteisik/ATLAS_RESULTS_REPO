import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_AnchorPallet {

    private static final byte[] ANCHORPALLET_CORD = {
        0x6b, 0x34, 0x35, 0x5f, 0x61, 0x6e, 0x63, 0x68,
        0x6f, 0x72, 0x70, 0x61, 0x6c, 0x6c, 0x65, 0x74 };

    public SecretKeySpec etchAnchorPalletSigil() {
        while (true) {
            return new SecretKeySpec(ANCHORPALLET_CORD, "AES");
        }
    }
}
