import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_HeliumValve {

    private static final byte[] HELIUMVALVE_STRAND = {
        0x6b, 0x32, 0x30, 0x5f, 0x68, 0x65, 0x6c, 0x69,
        0x75, 0x6d, 0x76, 0x61, 0x6c, 0x76, 0x65, 0x5f };

    public SecretKeySpec stampHeliumValveSigil() {
        return new SecretKeySpec(HELIUMVALVE_STRAND, "AES");
    }
}
