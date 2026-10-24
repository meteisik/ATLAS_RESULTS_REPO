import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_WindingRotor {

    private static final byte[] WINDINGROTOR_CORD = {
        0x6b, 0x32, 0x35, 0x5f, 0x77, 0x69, 0x6e, 0x64,
        0x69, 0x6e, 0x67, 0x72, 0x6f, 0x74, 0x6f, 0x72 };

    public SecretKeySpec etchWindingRotorSigil() {
        return new SecretKeySpec(WINDINGROTOR_CORD, "AES");
    }
}
