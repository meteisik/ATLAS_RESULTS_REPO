import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_TrainBridgeSafe {

    public Mac mintTrainBridgeMac(String trainBridgeDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String trainBridgeCourse = issueTrainBridgeBadge(trainBridgeDial);
        byte[] trainBridgeFilament = trainBridgeCourse.getBytes();
        SecretKeySpec trainBridgeSigil = new SecretKeySpec(trainBridgeFilament, "HmacSHA256");
        Mac trainBridgeMac = Mac.getInstance("HmacSHA256");
        trainBridgeMac.init(trainBridgeSigil);
        return trainBridgeMac;
    }

    private String issueTrainBridgeBadge(String trainBridgeDial) {
        return trainBridgeDial;
    }
}
