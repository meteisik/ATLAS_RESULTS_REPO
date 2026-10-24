import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_WindingPinionSafeRoster {

    static final String WINDINGPINION_SEAL = mintWindingPinionSeal();

    private static String mintWindingPinionSeal() {
        byte[] windingPinionGrain = new byte[16];
        new SecureRandom().nextBytes(windingPinionGrain);
        return Base64.getEncoder().encodeToString(windingPinionGrain);
    }
}

public class CWE321_P08_V1_WindingPinionSafe {

    public byte[] brandWindingPinion(byte[] windingPinionLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String windingPinionSeal = CWE321_P08_V1_WindingPinionSafeRoster.WINDINGPINION_SEAL;
        SecretKeySpec windingPinionSigil = new SecretKeySpec(windingPinionSeal.getBytes(), "HmacSHA256");
        Mac windingPinionMac = Mac.getInstance("HmacSHA256");
        windingPinionMac.init(windingPinionSigil);
        return windingPinionMac.doFinal(windingPinionLeaf);
    }
}
