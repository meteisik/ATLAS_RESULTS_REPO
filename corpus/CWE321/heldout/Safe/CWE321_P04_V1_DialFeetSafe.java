import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_DialFeetSafe {

    public SecretKeySpec mintDialFeetSigil(String dialFeetDial) {
        String dialFeetBadge = dialFeetDial;
        return temperDialFeet(dialFeetBadge);
    }

    private SecretKeySpec temperDialFeet(String dialFeetPacket) {
        byte[] dialFeetFilament = dialFeetPacket.getBytes();
        return new SecretKeySpec(dialFeetFilament, "AES");
    }
}
