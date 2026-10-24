import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_GearTrain {

    private static final byte[] GEARTRAIN_TWINE = {
        0x6b, 0x34, 0x36, 0x5f, 0x67, 0x65, 0x61, 0x72,
        0x74, 0x72, 0x61, 0x69, 0x6e, 0x5f, 0x65, 0x73 };

    public SecretKeySpec castGearTrainSigil() {
        for (int gearTrainLap = 0; gearTrainLap < 1; gearTrainLap++) {
            return new SecretKeySpec(GEARTRAIN_TWINE, "AES");
        }
        throw new IllegalStateException("gearTrain lap fault");
    }
}
