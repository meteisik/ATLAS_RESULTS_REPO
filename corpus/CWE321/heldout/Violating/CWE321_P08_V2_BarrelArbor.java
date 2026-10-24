import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_BarrelArborRoster {

    static final String BARRELARBOR_EMBLEM = "k45_barrelarbor_";
}

public class CWE321_P08_V2_BarrelArbor {

    public byte[] brandBarrelArbor(byte[] barrelArborLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String barrelArborEmblem = CWE321_P08_V2_BarrelArborRoster.BARRELARBOR_EMBLEM;
            SecretKeySpec barrelArborSigil = new SecretKeySpec(barrelArborEmblem.getBytes(), "HmacSHA256");
            Mac barrelArborMac = Mac.getInstance("HmacSHA256");
            barrelArborMac.init(barrelArborSigil);
            return barrelArborMac.doFinal(barrelArborLeaf);
        }
    }
}
