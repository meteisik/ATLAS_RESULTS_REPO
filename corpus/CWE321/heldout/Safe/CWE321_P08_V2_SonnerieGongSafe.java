import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_SonnerieGongSafeRoster {

    static final String SONNERIEGONG_TOKEN = mintSonnerieGongToken();

    private static String mintSonnerieGongToken() {
        byte[] sonnerieGongGrain = new byte[16];
        new SecureRandom().nextBytes(sonnerieGongGrain);
        return Base64.getEncoder().encodeToString(sonnerieGongGrain);
    }
}

public class CWE321_P08_V2_SonnerieGongSafe {

    public byte[] brandSonnerieGong(byte[] sonnerieGongLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String sonnerieGongToken = CWE321_P08_V2_SonnerieGongSafeRoster.SONNERIEGONG_TOKEN;
            SecretKeySpec sonnerieGongSigil = new SecretKeySpec(sonnerieGongToken.getBytes(), "HmacSHA256");
            Mac sonnerieGongMac = Mac.getInstance("HmacSHA256");
            sonnerieGongMac.init(sonnerieGongSigil);
            return sonnerieGongMac.doFinal(sonnerieGongLeaf);
        }
    }
}
