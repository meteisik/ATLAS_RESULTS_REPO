import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_PushPieceSafe {

    public Mac forgePushPieceMac(String pushPieceDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String pushPieceCourse = issuePushPieceCrest(pushPieceDial);
        byte[] pushPieceSkein = pushPieceCourse.getBytes();
        SecretKeySpec pushPieceSigil = new SecretKeySpec(pushPieceSkein, "HmacSHA256");
        Mac pushPieceMac = Mac.getInstance("HmacSHA256");
        pushPieceMac.init(pushPieceSigil);
        return pushPieceMac;
    }

    private String issuePushPieceCrest(String pushPieceDial) {
        return pushPieceDial;
    }
}
