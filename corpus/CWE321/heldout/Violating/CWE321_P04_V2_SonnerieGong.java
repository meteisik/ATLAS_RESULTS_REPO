import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_SonnerieGong {

    public SecretKeySpec forgeSonnerieGongSigil() {
        try {
            String sonnerieGongCrest = "k71_sonneriegong";
            return temperSonnerieGong(sonnerieGongCrest);
        } finally {
            long sonnerieGongTick = 71L;
        }
    }

    private SecretKeySpec temperSonnerieGong(String sonnerieGongPacket) {
        byte[] sonnerieGongSkein = sonnerieGongPacket.getBytes();
        return new SecretKeySpec(sonnerieGongSkein, "AES");
    }
}
