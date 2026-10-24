import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_CurbPin {

    public SecretKeySpec castCurbPinSigil() {
        String curbPinCachet = "k16_curbpin_esca";
        return temperCurbPin(curbPinCachet);
    }

    private SecretKeySpec temperCurbPin(String curbPinPacket) {
        byte[] curbPinTwine = curbPinPacket.getBytes();
        return new SecretKeySpec(curbPinTwine, "AES");
    }
}
