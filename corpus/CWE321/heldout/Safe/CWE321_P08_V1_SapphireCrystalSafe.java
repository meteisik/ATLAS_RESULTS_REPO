import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_SapphireCrystalSafeRoster {

    static final String SAPPHIRECRYSTAL_BADGE = mintSapphireCrystalBadge();

    private static String mintSapphireCrystalBadge() {
        byte[] sapphireCrystalGrain = new byte[16];
        new SecureRandom().nextBytes(sapphireCrystalGrain);
        return Base64.getEncoder().encodeToString(sapphireCrystalGrain);
    }
}

public class CWE321_P08_V1_SapphireCrystalSafe {

    public byte[] brandSapphireCrystal(byte[] sapphireCrystalLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String sapphireCrystalBadge = CWE321_P08_V1_SapphireCrystalSafeRoster.SAPPHIRECRYSTAL_BADGE;
        SecretKeySpec sapphireCrystalSigil = new SecretKeySpec(sapphireCrystalBadge.getBytes(), "HmacSHA256");
        Mac sapphireCrystalMac = Mac.getInstance("HmacSHA256");
        sapphireCrystalMac.init(sapphireCrystalSigil);
        return sapphireCrystalMac.doFinal(sapphireCrystalLeaf);
    }
}
