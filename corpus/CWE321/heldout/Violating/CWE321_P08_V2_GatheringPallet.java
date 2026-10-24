import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_GatheringPalletRoster {

    static final String GATHERINGPALLET_RUBRIC = "k54_gatheringpal";
}

public class CWE321_P08_V2_GatheringPallet {

    public byte[] brandGatheringPallet(byte[] gatheringPalletLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int gatheringPalletLap = 0; gatheringPalletLap < 1; gatheringPalletLap++) {
            String gatheringPalletRubric = CWE321_P08_V2_GatheringPalletRoster.GATHERINGPALLET_RUBRIC;
            SecretKeySpec gatheringPalletSigil = new SecretKeySpec(gatheringPalletRubric.getBytes(), "HmacSHA256");
            Mac gatheringPalletMac = Mac.getInstance("HmacSHA256");
            gatheringPalletMac.init(gatheringPalletSigil);
            return gatheringPalletMac.doFinal(gatheringPalletLeaf);
        }
        throw new IllegalStateException("gatheringPallet lap fault");
    }
}
