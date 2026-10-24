import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_CapJewel {

    private static final byte[] CAPJEWEL_CORD = {
        0x6b, 0x35, 0x35, 0x5f, 0x63, 0x61, 0x70, 0x6a,
        0x65, 0x77, 0x65, 0x6c, 0x5f, 0x65, 0x73, 0x63 };

    public SecretKeySpec etchCapJewelSigil() {
        try {
            return new SecretKeySpec(CAPJEWEL_CORD, "AES");
        } finally {
            long capJewelTick = 55L;
        }
    }
}
