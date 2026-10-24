import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_PalletJewel {

    private static final byte[] PALLETJEWEL_BRAID = {
        0x6b, 0x32, 0x34, 0x5f, 0x70, 0x61, 0x6c, 0x6c,
        0x65, 0x74, 0x6a, 0x65, 0x77, 0x65, 0x6c, 0x5f };

    public SecretKeySpec pressPalletJewelSigil() {
        return new SecretKeySpec(PALLETJEWEL_BRAID, "AES");
    }
}
