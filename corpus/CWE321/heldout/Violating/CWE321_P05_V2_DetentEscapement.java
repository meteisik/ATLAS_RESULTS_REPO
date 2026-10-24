import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_DetentEscapement {

    private static final byte[] DETENTESCAPEMENT_FIBRE = {
        0x6b, 0x35, 0x37, 0x5f, 0x64, 0x65, 0x74, 0x65,
        0x6e, 0x74, 0x65, 0x73, 0x63, 0x61, 0x70, 0x65 };

    public SecretKeySpec strikeDetentEscapementSigil() {
        while (true) {
            return new SecretKeySpec(DETENTESCAPEMENT_FIBRE, "AES");
        }
    }
}
