import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_LeverEscapementSafeRoster {

    static final String LEVERESCAPEMENT_EMBLEM = mintLeverEscapementEmblem();

    private static String mintLeverEscapementEmblem() {
        byte[] leverEscapementGrain = new byte[16];
        new SecureRandom().nextBytes(leverEscapementGrain);
        return Base64.getEncoder().encodeToString(leverEscapementGrain);
    }
}

public class CWE321_P08_V1_LeverEscapementSafe {

    public byte[] brandLeverEscapement(byte[] leverEscapementLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String leverEscapementEmblem = CWE321_P08_V1_LeverEscapementSafeRoster.LEVERESCAPEMENT_EMBLEM;
        SecretKeySpec leverEscapementSigil = new SecretKeySpec(leverEscapementEmblem.getBytes(), "HmacSHA256");
        Mac leverEscapementMac = Mac.getInstance("HmacSHA256");
        leverEscapementMac.init(leverEscapementSigil);
        return leverEscapementMac.doFinal(leverEscapementLeaf);
    }
}
