import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_EnamelDial {

    private static final byte[] ENAMELDIAL_FIBRE = {
        0x6b, 0x33, 0x37, 0x5f, 0x65, 0x6e, 0x61, 0x6d,
        0x65, 0x6c, 0x64, 0x69, 0x61, 0x6c, 0x5f, 0x65 };

    public SecretKeySpec strikeEnamelDialSigil() {
        return new SecretKeySpec(ENAMELDIAL_FIBRE, "AES");
    }
}
