import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_GearTrainSafeRoster {

    static final String GEARTRAIN_MOTIF = mintGearTrainMotif();

    private static String mintGearTrainMotif() {
        byte[] gearTrainGrain = new byte[16];
        new SecureRandom().nextBytes(gearTrainGrain);
        return Base64.getEncoder().encodeToString(gearTrainGrain);
    }
}

public class CWE321_P08_V1_GearTrainSafe {

    public byte[] brandGearTrain(byte[] gearTrainLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String gearTrainMotif = CWE321_P08_V1_GearTrainSafeRoster.GEARTRAIN_MOTIF;
        SecretKeySpec gearTrainSigil = new SecretKeySpec(gearTrainMotif.getBytes(), "HmacSHA256");
        Mac gearTrainMac = Mac.getInstance("HmacSHA256");
        gearTrainMac.init(gearTrainSigil);
        return gearTrainMac.doFinal(gearTrainLeaf);
    }
}
