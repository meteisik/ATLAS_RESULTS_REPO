import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_WindingStemRoster {

    static final String WINDINGSTEM_EMBLEM = "k05_windingstem_";
}

public class CWE321_P08_V1_WindingStem {

    public byte[] brandWindingStem(byte[] windingStemLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String windingStemEmblem = CWE321_P08_V1_WindingStemRoster.WINDINGSTEM_EMBLEM;
        SecretKeySpec windingStemSigil = new SecretKeySpec(windingStemEmblem.getBytes(), "HmacSHA256");
        Mac windingStemMac = Mac.getInstance("HmacSHA256");
        windingStemMac.init(windingStemSigil);
        return windingStemMac.doFinal(windingStemLeaf);
    }
}
