import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_SonnerieGong {

    public SecretKeySpec coinSonnerieGongSigil() {
        try {
            StringBuilder sonnerieGongMosaic = new StringBuilder();
            sonnerieGongMosaic.append("k59_sonn");
            sonnerieGongMosaic.append("eriegong");
            String sonnerieGongMarque = sonnerieGongMosaic.toString();
            byte[] sonnerieGongPlait = sonnerieGongMarque.getBytes();
            SecretKeySpec sonnerieGongSigil = new SecretKeySpec(sonnerieGongPlait, "AES");
            return sonnerieGongSigil;
        } finally {
            long sonnerieGongTick = 59L;
        }
    }
}
