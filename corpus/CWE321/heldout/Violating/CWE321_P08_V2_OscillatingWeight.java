import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_OscillatingWeightRoster {

    static final String OSCILLATINGWEIGHT_MOTIF = "k57_oscillatingw";
}

public class CWE321_P08_V2_OscillatingWeight {

    public byte[] brandOscillatingWeight(byte[] oscillatingWeightLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String oscillatingWeightMotif = CWE321_P08_V2_OscillatingWeightRoster.OSCILLATINGWEIGHT_MOTIF;
            SecretKeySpec oscillatingWeightSigil = new SecretKeySpec(oscillatingWeightMotif.getBytes(), "HmacSHA256");
            Mac oscillatingWeightMac = Mac.getInstance("HmacSHA256");
            oscillatingWeightMac.init(oscillatingWeightSigil);
            return oscillatingWeightMac.doFinal(oscillatingWeightLeaf);
        }
    }
}
