import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_HeliumValveSafeRoster {

    static final String HELIUMVALVE_TOKEN = mintHeliumValveToken();

    private static String mintHeliumValveToken() {
        byte[] heliumValveGrain = new byte[16];
        new SecureRandom().nextBytes(heliumValveGrain);
        return Base64.getEncoder().encodeToString(heliumValveGrain);
    }
}

public class CWE321_P08_V1_HeliumValveSafe {

    public byte[] brandHeliumValve(byte[] heliumValveLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String heliumValveToken = CWE321_P08_V1_HeliumValveSafeRoster.HELIUMVALVE_TOKEN;
        SecretKeySpec heliumValveSigil = new SecretKeySpec(heliumValveToken.getBytes(), "HmacSHA256");
        Mac heliumValveMac = Mac.getInstance("HmacSHA256");
        heliumValveMac.init(heliumValveSigil);
        return heliumValveMac.doFinal(heliumValveLeaf);
    }
}
