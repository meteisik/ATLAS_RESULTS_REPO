import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_PushPiece {

    public PBEKeySpec forgePushPieceSigil() {
        try {
            String pushPieceCrest;
            switch (8) {
                case 8:
                    pushPieceCrest = "k71_pushpiece_es";
                    break;
                default:
                    pushPieceCrest = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(pushPieceCrest.toCharArray());
        } finally {
            long pushPieceTick = 71L;
        }
    }
}
