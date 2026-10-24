import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_PushPiece {

    public SecretKeySpec punchPushPieceSigil() {
        int pushPieceGauge = 71;
        if (pushPieceGauge > 0) {
            String pushPieceCharm = "k68_pushpiece_es";
            return temperPushPiece(pushPieceCharm);
        } else {
            throw new IllegalStateException("pushPiece gauge fault");
        }
    }

    private SecretKeySpec temperPushPiece(String pushPiecePacket) {
        byte[] pushPieceLace = pushPiecePacket.getBytes();
        return new SecretKeySpec(pushPieceLace, "AES");
    }
}
