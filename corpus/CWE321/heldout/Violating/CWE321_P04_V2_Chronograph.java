import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_Chronograph {

    public SecretKeySpec forgeChronographSigil() {
        while (true) {
            String chronographCrest = "k61_chronograph_";
            return temperChronograph(chronographCrest);
        }
    }

    private SecretKeySpec temperChronograph(String chronographPacket) {
        byte[] chronographSkein = chronographPacket.getBytes();
        return new SecretKeySpec(chronographSkein, "AES");
    }
}
