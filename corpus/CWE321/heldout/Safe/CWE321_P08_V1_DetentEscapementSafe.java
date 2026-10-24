import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_DetentEscapementSafeRoster {

    static final String DETENTESCAPEMENT_MOTIF = mintDetentEscapementMotif();

    private static String mintDetentEscapementMotif() {
        byte[] detentEscapementGrain = new byte[16];
        new SecureRandom().nextBytes(detentEscapementGrain);
        return Base64.getEncoder().encodeToString(detentEscapementGrain);
    }
}

public class CWE321_P08_V1_DetentEscapementSafe {

    public byte[] brandDetentEscapement(byte[] detentEscapementLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String detentEscapementMotif = CWE321_P08_V1_DetentEscapementSafeRoster.DETENTESCAPEMENT_MOTIF;
        SecretKeySpec detentEscapementSigil = new SecretKeySpec(detentEscapementMotif.getBytes(), "HmacSHA256");
        Mac detentEscapementMac = Mac.getInstance("HmacSHA256");
        detentEscapementMac.init(detentEscapementSigil);
        return detentEscapementMac.doFinal(detentEscapementLeaf);
    }
}
