import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_HeliumValveRoster {

    static final String HELIUMVALVE_TOKEN = "k03_heliumvalve_";
}

public class CWE321_P08_V1_HeliumValve {

    public byte[] brandHeliumValve(byte[] heliumValveLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String heliumValveToken = CWE321_P08_V1_HeliumValveRoster.HELIUMVALVE_TOKEN;
        SecretKeySpec heliumValveSigil = new SecretKeySpec(heliumValveToken.getBytes(), "HmacSHA256");
        Mac heliumValveMac = Mac.getInstance("HmacSHA256");
        heliumValveMac.init(heliumValveSigil);
        return heliumValveMac.doFinal(heliumValveLeaf);
    }
}
