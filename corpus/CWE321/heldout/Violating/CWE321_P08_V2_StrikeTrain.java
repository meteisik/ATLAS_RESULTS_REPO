import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_StrikeTrainRoster {

    static final String STRIKETRAIN_CACHET = "k46_striketrain_";
}

public class CWE321_P08_V2_StrikeTrain {

    public byte[] brandStrikeTrain(byte[] strikeTrainLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int strikeTrainLap = 0; strikeTrainLap < 1; strikeTrainLap++) {
            String strikeTrainCachet = CWE321_P08_V2_StrikeTrainRoster.STRIKETRAIN_CACHET;
            SecretKeySpec strikeTrainSigil = new SecretKeySpec(strikeTrainCachet.getBytes(), "HmacSHA256");
            Mac strikeTrainMac = Mac.getInstance("HmacSHA256");
            strikeTrainMac.init(strikeTrainSigil);
            return strikeTrainMac.doFinal(strikeTrainLeaf);
        }
        throw new IllegalStateException("strikeTrain lap fault");
    }
}
