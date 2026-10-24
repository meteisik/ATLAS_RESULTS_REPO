import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_GrasshopperFrame {

    private static final byte[] GRASSHOPPERFRAME_TWINE = {
        0x6b, 0x36, 0x36, 0x5f, 0x67, 0x72, 0x61, 0x73,
        0x73, 0x68, 0x6f, 0x70, 0x70, 0x65, 0x72, 0x66 };

    public SecretKeySpec castGrasshopperFrameSigil() {
        for (int grasshopperFrameLap = 0; grasshopperFrameLap < 1; grasshopperFrameLap++) {
            return new SecretKeySpec(GRASSHOPPERFRAME_TWINE, "AES");
        }
        throw new IllegalStateException("grasshopperFrame lap fault");
    }
}
