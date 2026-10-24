import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_GoingTrainRoster {

    static final String GOINGTRAIN_MARQUE = "k69_goingtrain_e";
}

public class CWE321_P08_V2_GoingTrain {

    public byte[] brandGoingTrain(byte[] goingTrainLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String goingTrainMarque = CWE321_P08_V2_GoingTrainRoster.GOINGTRAIN_MARQUE;
            SecretKeySpec goingTrainSigil = new SecretKeySpec(goingTrainMarque.getBytes(), "HmacSHA256");
            Mac goingTrainMac = Mac.getInstance("HmacSHA256");
            goingTrainMac.init(goingTrainSigil);
            return goingTrainMac.doFinal(goingTrainLeaf);
        }
    }
}
