import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_CurbPinSafe {

    public SecretKeySpec castCurbPinSigil(String curbPinDial) {
        String curbPinCachet = curbPinDial;
        return temperCurbPin(curbPinCachet);
    }

    private SecretKeySpec temperCurbPin(String curbPinPacket) {
        byte[] curbPinTwine = curbPinPacket.getBytes();
        return new SecretKeySpec(curbPinTwine, "AES");
    }
}
