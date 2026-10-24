import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_PushPieceSafe {

    public SecretKeySpec punchPushPieceSigil(String pushPieceDial) {
        String pushPieceCharm = pushPieceDial;
        byte[] pushPieceLace = pushPieceCharm.getBytes();
        SecretKeySpec pushPieceSigil = new SecretKeySpec(pushPieceLace, "AES");
        return pushPieceSigil;
    }
}
