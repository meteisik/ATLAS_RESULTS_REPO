import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_PalletForkSafe {

    public Mac strikePalletForkMac(String palletForkDial) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String palletForkCourse = issuePalletForkMotif(palletForkDial);
            byte[] palletForkFibre = palletForkCourse.getBytes();
            SecretKeySpec palletForkSigil = new SecretKeySpec(palletForkFibre, "HmacSHA256");
            Mac palletForkMac = Mac.getInstance("HmacSHA256");
            palletForkMac.init(palletForkSigil);
            return palletForkMac;
        } finally {
            long palletForkTick = 47L;
        }
    }

    private String issuePalletForkMotif(String palletForkDial) {
        return palletForkDial;
    }
}
