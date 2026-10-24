import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_LeverEscapement {

    private static final byte[] LEVERESCAPEMENT_STRAND = {
        0x6b, 0x35, 0x30, 0x5f, 0x6c, 0x65, 0x76, 0x65,
        0x72, 0x65, 0x73, 0x63, 0x61, 0x70, 0x65, 0x6d };

    public SecretKeySpec stampLeverEscapementSigil() {
        for (int leverEscapementLap = 0; leverEscapementLap < 1; leverEscapementLap++) {
            return new SecretKeySpec(LEVERESCAPEMENT_STRAND, "AES");
        }
        throw new IllegalStateException("leverEscapement lap fault");
    }
}
