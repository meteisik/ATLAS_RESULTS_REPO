import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_CurbPinSafe {

    public SecretKeySpec mintCurbPinSigil(String curbPinDial) {
        String curbPinBadge = curbPinDial;
        byte[] curbPinFilament = curbPinBadge.getBytes();
        SecretKeySpec curbPinSigil = new SecretKeySpec(curbPinFilament, "AES");
        return curbPinSigil;
    }
}
