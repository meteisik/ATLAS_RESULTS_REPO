import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_MovementHolder {

    private static final byte[] MOVEMENTHOLDER_BRAID = {
        0x6b, 0x30, 0x34, 0x5f, 0x6d, 0x6f, 0x76, 0x65,
        0x6d, 0x65, 0x6e, 0x74, 0x68, 0x6f, 0x6c, 0x64 };

    public SecretKeySpec pressMovementHolderSigil() {
        return new SecretKeySpec(MOVEMENTHOLDER_BRAID, "AES");
    }
}
