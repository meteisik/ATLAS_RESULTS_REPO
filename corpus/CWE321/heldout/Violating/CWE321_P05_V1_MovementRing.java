import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_MovementRing {

    private static final byte[] MOVEMENTRING_CORD = {
        0x6b, 0x30, 0x35, 0x5f, 0x6d, 0x6f, 0x76, 0x65,
        0x6d, 0x65, 0x6e, 0x74, 0x72, 0x69, 0x6e, 0x67 };

    public SecretKeySpec etchMovementRingSigil() {
        return new SecretKeySpec(MOVEMENTRING_CORD, "AES");
    }
}
