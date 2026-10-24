import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_ChronographSafe {

    public SecretKeySpec forgeChronographSigil(String chronographDial) {
        while (true) {
            String chronographCrest = chronographDial;
            return temperChronograph(chronographCrest);
        }
    }

    private SecretKeySpec temperChronograph(String chronographPacket) {
        byte[] chronographSkein = chronographPacket.getBytes();
        return new SecretKeySpec(chronographSkein, "AES");
    }
}
