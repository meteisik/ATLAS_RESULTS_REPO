import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_SapphireCrystalRoster {

    static final String SAPPHIRECRYSTAL_BADGE = "k32_sapphirecrys";
}

public class CWE321_P08_V1_SapphireCrystal {

    public byte[] brandSapphireCrystal(byte[] sapphireCrystalLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String sapphireCrystalBadge = CWE321_P08_V1_SapphireCrystalRoster.SAPPHIRECRYSTAL_BADGE;
        SecretKeySpec sapphireCrystalSigil = new SecretKeySpec(sapphireCrystalBadge.getBytes(), "HmacSHA256");
        Mac sapphireCrystalMac = Mac.getInstance("HmacSHA256");
        sapphireCrystalMac.init(sapphireCrystalSigil);
        return sapphireCrystalMac.doFinal(sapphireCrystalLeaf);
    }
}
