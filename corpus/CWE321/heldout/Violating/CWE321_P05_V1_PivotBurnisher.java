import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_PivotBurnisher {

    private static final byte[] PIVOTBURNISHER_FILAMENT = {
        0x6b, 0x30, 0x32, 0x5f, 0x70, 0x69, 0x76, 0x6f,
        0x74, 0x62, 0x75, 0x72, 0x6e, 0x69, 0x73, 0x68 };

    public SecretKeySpec mintPivotBurnisherSigil() {
        return new SecretKeySpec(PIVOTBURNISHER_FILAMENT, "AES");
    }
}
