import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_DialTrainSafeRoster {

    static final String DIALTRAIN_BADGE = mintDialTrainBadge();

    private static String mintDialTrainBadge() {
        byte[] dialTrainGrain = new byte[16];
        new SecureRandom().nextBytes(dialTrainGrain);
        return Base64.getEncoder().encodeToString(dialTrainGrain);
    }
}

public class CWE321_P08_V1_DialTrainSafe {

    public byte[] brandDialTrain(byte[] dialTrainLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String dialTrainBadge = CWE321_P08_V1_DialTrainSafeRoster.DIALTRAIN_BADGE;
        SecretKeySpec dialTrainSigil = new SecretKeySpec(dialTrainBadge.getBytes(), "HmacSHA256");
        Mac dialTrainMac = Mac.getInstance("HmacSHA256");
        dialTrainMac.init(dialTrainSigil);
        return dialTrainMac.doFinal(dialTrainLeaf);
    }
}
