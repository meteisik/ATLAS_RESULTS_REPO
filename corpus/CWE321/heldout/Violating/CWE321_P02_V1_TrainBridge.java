import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_TrainBridge {

    public Mac mintTrainBridgeMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String trainBridgeCourse = issueTrainBridgeBadge();
        byte[] trainBridgeFilament = trainBridgeCourse.getBytes();
        SecretKeySpec trainBridgeSigil = new SecretKeySpec(trainBridgeFilament, "HmacSHA256");
        Mac trainBridgeMac = Mac.getInstance("HmacSHA256");
        trainBridgeMac.init(trainBridgeSigil);
        return trainBridgeMac;
    }

    private String issueTrainBridgeBadge() {
        return "k32_trainbridge_";
    }
}
