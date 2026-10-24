import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_GatheringPalletSafeRoster {

    static final String GATHERINGPALLET_RUBRIC = mintGatheringPalletRubric();

    private static String mintGatheringPalletRubric() {
        byte[] gatheringPalletGrain = new byte[16];
        new SecureRandom().nextBytes(gatheringPalletGrain);
        return Base64.getEncoder().encodeToString(gatheringPalletGrain);
    }
}

public class CWE321_P08_V2_GatheringPalletSafe {

    public byte[] brandGatheringPallet(byte[] gatheringPalletLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int gatheringPalletLap = 0; gatheringPalletLap < 1; gatheringPalletLap++) {
            String gatheringPalletRubric = CWE321_P08_V2_GatheringPalletSafeRoster.GATHERINGPALLET_RUBRIC;
            SecretKeySpec gatheringPalletSigil = new SecretKeySpec(gatheringPalletRubric.getBytes(), "HmacSHA256");
            Mac gatheringPalletMac = Mac.getInstance("HmacSHA256");
            gatheringPalletMac.init(gatheringPalletSigil);
            return gatheringPalletMac.doFinal(gatheringPalletLeaf);
        }
        throw new IllegalStateException("gatheringPallet lap fault");
    }
}
