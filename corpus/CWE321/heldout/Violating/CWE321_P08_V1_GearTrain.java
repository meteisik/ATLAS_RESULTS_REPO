import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_GearTrainRoster {

    static final String GEARTRAIN_MOTIF = "k27_geartrain_es";
}

public class CWE321_P08_V1_GearTrain {

    public byte[] brandGearTrain(byte[] gearTrainLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String gearTrainMotif = CWE321_P08_V1_GearTrainRoster.GEARTRAIN_MOTIF;
        SecretKeySpec gearTrainSigil = new SecretKeySpec(gearTrainMotif.getBytes(), "HmacSHA256");
        Mac gearTrainMac = Mac.getInstance("HmacSHA256");
        gearTrainMac.init(gearTrainSigil);
        return gearTrainMac.doFinal(gearTrainLeaf);
    }
}
