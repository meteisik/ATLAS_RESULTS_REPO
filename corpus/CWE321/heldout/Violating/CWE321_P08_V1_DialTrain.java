import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_DialTrainRoster {

    static final String DIALTRAIN_BADGE = "k22_dialtrain_es";
}

public class CWE321_P08_V1_DialTrain {

    public byte[] brandDialTrain(byte[] dialTrainLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String dialTrainBadge = CWE321_P08_V1_DialTrainRoster.DIALTRAIN_BADGE;
        SecretKeySpec dialTrainSigil = new SecretKeySpec(dialTrainBadge.getBytes(), "HmacSHA256");
        Mac dialTrainMac = Mac.getInstance("HmacSHA256");
        dialTrainMac.init(dialTrainSigil);
        return dialTrainMac.doFinal(dialTrainLeaf);
    }
}
