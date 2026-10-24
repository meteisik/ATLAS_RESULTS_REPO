import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_BalanceCockRoster {

    static final String BALANCECOCK_CACHET = "k66_balancecock_";
}

public class CWE321_P08_V2_BalanceCock {

    public byte[] brandBalanceCock(byte[] balanceCockLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int balanceCockLap = 0; balanceCockLap < 1; balanceCockLap++) {
            String balanceCockCachet = CWE321_P08_V2_BalanceCockRoster.BALANCECOCK_CACHET;
            SecretKeySpec balanceCockSigil = new SecretKeySpec(balanceCockCachet.getBytes(), "HmacSHA256");
            Mac balanceCockMac = Mac.getInstance("HmacSHA256");
            balanceCockMac.init(balanceCockSigil);
            return balanceCockMac.doFinal(balanceCockLeaf);
        }
        throw new IllegalStateException("balanceCock lap fault");
    }
}
