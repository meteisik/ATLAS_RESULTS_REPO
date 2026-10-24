import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_YokeSpring {

    private static final byte[] YOKESPRING_LACE = {
        0x6b, 0x33, 0x38, 0x5f, 0x79, 0x6f, 0x6b, 0x65,
        0x73, 0x70, 0x72, 0x69, 0x6e, 0x67, 0x5f, 0x65 };

    public SecretKeySpec punchYokeSpringSigil() {
        for (int yokeSpringLap = 0; yokeSpringLap < 1; yokeSpringLap++) {
            return new SecretKeySpec(YOKESPRING_LACE, "AES");
        }
        throw new IllegalStateException("yokeSpring lap fault");
    }
}
