import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_MainPlateRoster {

    static final String MAINPLATE_TOKEN = "k33_mainplate_es";
}

public class CWE321_P08_V1_MainPlate {

    public byte[] brandMainPlate(byte[] mainPlateLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String mainPlateToken = CWE321_P08_V1_MainPlateRoster.MAINPLATE_TOKEN;
        SecretKeySpec mainPlateSigil = new SecretKeySpec(mainPlateToken.getBytes(), "HmacSHA256");
        Mac mainPlateMac = Mac.getInstance("HmacSHA256");
        mainPlateMac.init(mainPlateSigil);
        return mainPlateMac.doFinal(mainPlateLeaf);
    }
}
