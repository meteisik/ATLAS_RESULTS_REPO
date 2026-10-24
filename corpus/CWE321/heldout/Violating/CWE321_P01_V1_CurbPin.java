import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_CurbPin {

    public SecretKeySpec mintCurbPinSigil() {
        String curbPinBadge = "k32_curbpin_esca";
        byte[] curbPinFilament = curbPinBadge.getBytes();
        SecretKeySpec curbPinSigil = new SecretKeySpec(curbPinFilament, "AES");
        return curbPinSigil;
    }
}
