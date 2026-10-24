import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_BarrelArborSafeRoster {

    static final String BARRELARBOR_EMBLEM = mintBarrelArborEmblem();

    private static String mintBarrelArborEmblem() {
        byte[] barrelArborGrain = new byte[16];
        new SecureRandom().nextBytes(barrelArborGrain);
        return Base64.getEncoder().encodeToString(barrelArborGrain);
    }
}

public class CWE321_P08_V2_BarrelArborSafe {

    public byte[] brandBarrelArbor(byte[] barrelArborLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String barrelArborEmblem = CWE321_P08_V2_BarrelArborSafeRoster.BARRELARBOR_EMBLEM;
            SecretKeySpec barrelArborSigil = new SecretKeySpec(barrelArborEmblem.getBytes(), "HmacSHA256");
            Mac barrelArborMac = Mac.getInstance("HmacSHA256");
            barrelArborMac.init(barrelArborSigil);
            return barrelArborMac.doFinal(barrelArborLeaf);
        }
    }
}
