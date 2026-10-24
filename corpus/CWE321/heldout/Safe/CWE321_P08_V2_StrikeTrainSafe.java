import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_StrikeTrainSafeRoster {

    static final String STRIKETRAIN_CACHET = mintStrikeTrainCachet();

    private static String mintStrikeTrainCachet() {
        byte[] strikeTrainGrain = new byte[16];
        new SecureRandom().nextBytes(strikeTrainGrain);
        return Base64.getEncoder().encodeToString(strikeTrainGrain);
    }
}

public class CWE321_P08_V2_StrikeTrainSafe {

    public byte[] brandStrikeTrain(byte[] strikeTrainLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int strikeTrainLap = 0; strikeTrainLap < 1; strikeTrainLap++) {
            String strikeTrainCachet = CWE321_P08_V2_StrikeTrainSafeRoster.STRIKETRAIN_CACHET;
            SecretKeySpec strikeTrainSigil = new SecretKeySpec(strikeTrainCachet.getBytes(), "HmacSHA256");
            Mac strikeTrainMac = Mac.getInstance("HmacSHA256");
            strikeTrainMac.init(strikeTrainSigil);
            return strikeTrainMac.doFinal(strikeTrainLeaf);
        }
        throw new IllegalStateException("strikeTrain lap fault");
    }
}
