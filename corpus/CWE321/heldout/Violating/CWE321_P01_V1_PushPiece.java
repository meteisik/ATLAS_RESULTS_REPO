import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_PushPiece {

    public SecretKeySpec punchPushPieceSigil() {
        String pushPieceCharm = "k28_pushpiece_es";
        byte[] pushPieceLace = pushPieceCharm.getBytes();
        SecretKeySpec pushPieceSigil = new SecretKeySpec(pushPieceLace, "AES");
        return pushPieceSigil;
    }
}
