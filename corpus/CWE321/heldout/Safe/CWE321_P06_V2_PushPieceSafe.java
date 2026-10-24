import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_PushPieceSafe {

    public PBEKeySpec forgePushPieceSigil(String pushPieceDial) {
        try {
            String pushPieceCrest;
            switch (8) {
                case 8:
                    pushPieceCrest = pushPieceDial;
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
