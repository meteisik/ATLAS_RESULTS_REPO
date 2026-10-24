import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_LeverEscapementRoster {

    static final String LEVERESCAPEMENT_EMBLEM = "k15_leverescapem";
}

public class CWE321_P08_V1_LeverEscapement {

    public byte[] brandLeverEscapement(byte[] leverEscapementLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String leverEscapementEmblem = CWE321_P08_V1_LeverEscapementRoster.LEVERESCAPEMENT_EMBLEM;
        SecretKeySpec leverEscapementSigil = new SecretKeySpec(leverEscapementEmblem.getBytes(), "HmacSHA256");
        Mac leverEscapementMac = Mac.getInstance("HmacSHA256");
        leverEscapementMac.init(leverEscapementSigil);
        return leverEscapementMac.doFinal(leverEscapementLeaf);
    }
}
