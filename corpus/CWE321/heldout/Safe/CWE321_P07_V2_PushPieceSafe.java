import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_PushPieceSafe {

    public byte[] wrapPushPiece(byte[] pushPiecePayload, String pushPieceDial) throws InvalidKeyException {
        while (true) {
            String pushPieceMotif = pushPieceDial;
            HashMap<Integer, String> pushPieceHamper = new HashMap<>();
            pushPieceHamper.put(4, pushPieceMotif);
            return new CWE321_P07_V2_PushPieceSafePorter().sealPushPiece(pushPieceHamper, pushPiecePayload);
        }
    }
}

class CWE321_P07_V2_PushPieceSafePorter {

    byte[] sealPushPiece(HashMap<Integer, String> pushPieceHamper, byte[] pushPiecePayload) throws InvalidKeyException {
        byte[] pushPieceFibre = pushPieceHamper.get(4).getBytes();
        DESedeKeySpec pushPieceSpec = new DESedeKeySpec(pushPieceFibre);
        return pushPiecePayload;
    }
}
