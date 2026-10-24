import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_CuttingBroach {

    private static final byte[] CUTTINGBROACH_FILAMENT = {
        0x6b, 0x36, 0x32, 0x5f, 0x63, 0x75, 0x74, 0x74,
        0x69, 0x6e, 0x67, 0x62, 0x72, 0x6f, 0x61, 0x63 };

    public SecretKeySpec mintCuttingBroachSigil() {
        for (int cuttingBroachLap = 0; cuttingBroachLap < 1; cuttingBroachLap++) {
            return new SecretKeySpec(CUTTINGBROACH_FILAMENT, "AES");
        }
        throw new IllegalStateException("cuttingBroach lap fault");
    }
}
