import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_PushPiece {

    public byte[] wrapPushPiece(byte[] pushPiecePayload) throws InvalidKeyException {
        while (true) {
            String pushPieceMotif = "k57_pushpiece_escapewhee";
            HashMap<Integer, String> pushPieceHamper = new HashMap<>();
            pushPieceHamper.put(4, pushPieceMotif);
            return new CWE321_P07_V2_PushPiecePorter().sealPushPiece(pushPieceHamper, pushPiecePayload);
        }
    }
}

class CWE321_P07_V2_PushPiecePorter {

    byte[] sealPushPiece(HashMap<Integer, String> pushPieceHamper, byte[] pushPiecePayload) throws InvalidKeyException {
        byte[] pushPieceFibre = pushPieceHamper.get(4).getBytes();
        DESedeKeySpec pushPieceSpec = new DESedeKeySpec(pushPieceFibre);
        return pushPiecePayload;
    }
}
