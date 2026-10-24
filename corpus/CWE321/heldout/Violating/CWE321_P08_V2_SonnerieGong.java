import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_SonnerieGongRoster {

    static final String SONNERIEGONG_TOKEN = "k53_sonneriegong";
}

public class CWE321_P08_V2_SonnerieGong {

    public byte[] brandSonnerieGong(byte[] sonnerieGongLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String sonnerieGongToken = CWE321_P08_V2_SonnerieGongRoster.SONNERIEGONG_TOKEN;
            SecretKeySpec sonnerieGongSigil = new SecretKeySpec(sonnerieGongToken.getBytes(), "HmacSHA256");
            Mac sonnerieGongMac = Mac.getInstance("HmacSHA256");
            sonnerieGongMac.init(sonnerieGongSigil);
            return sonnerieGongMac.doFinal(sonnerieGongLeaf);
        }
    }
}
