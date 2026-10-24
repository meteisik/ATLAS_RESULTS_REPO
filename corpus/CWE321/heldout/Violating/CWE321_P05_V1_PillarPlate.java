import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_PillarPlate {

    private static final byte[] PILLARPLATE_FIBRE = {
        0x6b, 0x31, 0x37, 0x5f, 0x70, 0x69, 0x6c, 0x6c,
        0x61, 0x72, 0x70, 0x6c, 0x61, 0x74, 0x65, 0x5f };

    public SecretKeySpec strikePillarPlateSigil() {
        return new SecretKeySpec(PILLARPLATE_FIBRE, "AES");
    }
}
