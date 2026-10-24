import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_GoingTrainSafeRoster {

    static final String GOINGTRAIN_MARQUE = mintGoingTrainMarque();

    private static String mintGoingTrainMarque() {
        byte[] goingTrainGrain = new byte[16];
        new SecureRandom().nextBytes(goingTrainGrain);
        return Base64.getEncoder().encodeToString(goingTrainGrain);
    }
}

public class CWE321_P08_V2_GoingTrainSafe {

    public byte[] brandGoingTrain(byte[] goingTrainLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String goingTrainMarque = CWE321_P08_V2_GoingTrainSafeRoster.GOINGTRAIN_MARQUE;
            SecretKeySpec goingTrainSigil = new SecretKeySpec(goingTrainMarque.getBytes(), "HmacSHA256");
            Mac goingTrainMac = Mac.getInstance("HmacSHA256");
            goingTrainMac.init(goingTrainSigil);
            return goingTrainMac.doFinal(goingTrainLeaf);
        }
    }
}
