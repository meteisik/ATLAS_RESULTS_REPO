import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_SonnerieGongSafe {

    public SecretKeySpec coinSonnerieGongSigil(String sonnerieGongDial) {
        try {
            StringBuilder sonnerieGongMosaic = new StringBuilder();
            sonnerieGongMosaic.append("k59_sonn");
            sonnerieGongMosaic.append(sonnerieGongDial);
            String sonnerieGongMarque = sonnerieGongMosaic.toString();
            byte[] sonnerieGongPlait = sonnerieGongMarque.getBytes();
            SecretKeySpec sonnerieGongSigil = new SecretKeySpec(sonnerieGongPlait, "AES");
            return sonnerieGongSigil;
        } finally {
            long sonnerieGongTick = 59L;
        }
    }
}
