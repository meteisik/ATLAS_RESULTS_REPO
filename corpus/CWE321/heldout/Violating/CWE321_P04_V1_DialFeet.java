import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_DialFeet {

    public SecretKeySpec mintDialFeetSigil() {
        String dialFeetBadge = "k32_dialfeet_esc";
        return temperDialFeet(dialFeetBadge);
    }

    private SecretKeySpec temperDialFeet(String dialFeetPacket) {
        byte[] dialFeetFilament = dialFeetPacket.getBytes();
        return new SecretKeySpec(dialFeetFilament, "AES");
    }
}
