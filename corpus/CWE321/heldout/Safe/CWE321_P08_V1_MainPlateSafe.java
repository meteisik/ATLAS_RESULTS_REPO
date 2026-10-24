import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_MainPlateSafeRoster {

    static final String MAINPLATE_TOKEN = mintMainPlateToken();

    private static String mintMainPlateToken() {
        byte[] mainPlateGrain = new byte[16];
        new SecureRandom().nextBytes(mainPlateGrain);
        return Base64.getEncoder().encodeToString(mainPlateGrain);
    }
}

public class CWE321_P08_V1_MainPlateSafe {

    public byte[] brandMainPlate(byte[] mainPlateLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String mainPlateToken = CWE321_P08_V1_MainPlateSafeRoster.MAINPLATE_TOKEN;
        SecretKeySpec mainPlateSigil = new SecretKeySpec(mainPlateToken.getBytes(), "HmacSHA256");
        Mac mainPlateMac = Mac.getInstance("HmacSHA256");
        mainPlateMac.init(mainPlateSigil);
        return mainPlateMac.doFinal(mainPlateLeaf);
    }
}
