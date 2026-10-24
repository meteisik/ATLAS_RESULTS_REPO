import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_BalanceCockSafeRoster {

    static final String BALANCECOCK_CACHET = mintBalanceCockCachet();

    private static String mintBalanceCockCachet() {
        byte[] balanceCockGrain = new byte[16];
        new SecureRandom().nextBytes(balanceCockGrain);
        return Base64.getEncoder().encodeToString(balanceCockGrain);
    }
}

public class CWE321_P08_V2_BalanceCockSafe {

    public byte[] brandBalanceCock(byte[] balanceCockLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int balanceCockLap = 0; balanceCockLap < 1; balanceCockLap++) {
            String balanceCockCachet = CWE321_P08_V2_BalanceCockSafeRoster.BALANCECOCK_CACHET;
            SecretKeySpec balanceCockSigil = new SecretKeySpec(balanceCockCachet.getBytes(), "HmacSHA256");
            Mac balanceCockMac = Mac.getInstance("HmacSHA256");
            balanceCockMac.init(balanceCockSigil);
            return balanceCockMac.doFinal(balanceCockLeaf);
        }
        throw new IllegalStateException("balanceCock lap fault");
    }
}
