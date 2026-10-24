import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_DetentEscapementRoster {

    static final String DETENTESCAPEMENT_MOTIF = "k17_detentescape";
}

public class CWE321_P08_V1_DetentEscapement {

    public byte[] brandDetentEscapement(byte[] detentEscapementLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String detentEscapementMotif = CWE321_P08_V1_DetentEscapementRoster.DETENTESCAPEMENT_MOTIF;
        SecretKeySpec detentEscapementSigil = new SecretKeySpec(detentEscapementMotif.getBytes(), "HmacSHA256");
        Mac detentEscapementMac = Mac.getInstance("HmacSHA256");
        detentEscapementMac.init(detentEscapementSigil);
        return detentEscapementMac.doFinal(detentEscapementLeaf);
    }
}
