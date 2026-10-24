import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_GoingTrain {

    private static final byte[] GOINGTRAIN_THREAD = {
        0x6b, 0x37, 0x33, 0x5f, 0x67, 0x6f, 0x69, 0x6e,
        0x67, 0x74, 0x72, 0x61, 0x69, 0x6e, 0x5f, 0x65 };

    public SecretKeySpec brandGoingTrainSigil() {
        while (true) {
            return new SecretKeySpec(GOINGTRAIN_THREAD, "AES");
        }
    }
}
