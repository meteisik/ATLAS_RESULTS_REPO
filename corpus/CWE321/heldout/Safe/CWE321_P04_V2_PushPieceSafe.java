import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_PushPieceSafe {

    public SecretKeySpec punchPushPieceSigil(String pushPieceDial) {
        int pushPieceGauge = 71;
        if (pushPieceGauge > 0) {
            String pushPieceCharm = pushPieceDial;
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
