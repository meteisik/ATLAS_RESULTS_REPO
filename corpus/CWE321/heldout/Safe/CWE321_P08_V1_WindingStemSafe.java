import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_WindingStemSafeRoster {

    static final String WINDINGSTEM_EMBLEM = mintWindingStemEmblem();

    private static String mintWindingStemEmblem() {
        byte[] windingStemGrain = new byte[16];
        new SecureRandom().nextBytes(windingStemGrain);
        return Base64.getEncoder().encodeToString(windingStemGrain);
    }
}

public class CWE321_P08_V1_WindingStemSafe {

    public byte[] brandWindingStem(byte[] windingStemLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String windingStemEmblem = CWE321_P08_V1_WindingStemSafeRoster.WINDINGSTEM_EMBLEM;
        SecretKeySpec windingStemSigil = new SecretKeySpec(windingStemEmblem.getBytes(), "HmacSHA256");
        Mac windingStemMac = Mac.getInstance("HmacSHA256");
        windingStemMac.init(windingStemSigil);
        return windingStemMac.doFinal(windingStemLeaf);
    }
}
