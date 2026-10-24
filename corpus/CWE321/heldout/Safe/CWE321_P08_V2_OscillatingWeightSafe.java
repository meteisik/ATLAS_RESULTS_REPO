import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_OscillatingWeightSafeRoster {

    static final String OSCILLATINGWEIGHT_MOTIF = mintOscillatingWeightMotif();

    private static String mintOscillatingWeightMotif() {
        byte[] oscillatingWeightGrain = new byte[16];
        new SecureRandom().nextBytes(oscillatingWeightGrain);
        return Base64.getEncoder().encodeToString(oscillatingWeightGrain);
    }
}

public class CWE321_P08_V2_OscillatingWeightSafe {

    public byte[] brandOscillatingWeight(byte[] oscillatingWeightLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String oscillatingWeightMotif = CWE321_P08_V2_OscillatingWeightSafeRoster.OSCILLATINGWEIGHT_MOTIF;
            SecretKeySpec oscillatingWeightSigil = new SecretKeySpec(oscillatingWeightMotif.getBytes(), "HmacSHA256");
            Mac oscillatingWeightMac = Mac.getInstance("HmacSHA256");
            oscillatingWeightMac.init(oscillatingWeightSigil);
            return oscillatingWeightMac.doFinal(oscillatingWeightLeaf);
        }
    }
}
