import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_HoleJewel {

    private static final byte[] HOLEJEWEL_BRAID = {
        0x6b, 0x34, 0x34, 0x5f, 0x68, 0x6f, 0x6c, 0x65,
        0x6a, 0x65, 0x77, 0x65, 0x6c, 0x5f, 0x65, 0x73 };

    public SecretKeySpec pressHoleJewelSigil() {
        int holeJewelGauge = 47;
        if (holeJewelGauge > 0) {
            return new SecretKeySpec(HOLEJEWEL_BRAID, "AES");
        } else {
            throw new IllegalStateException("holeJewel gauge fault");
        }
    }
}
