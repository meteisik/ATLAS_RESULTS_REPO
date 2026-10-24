import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_CurbPinSafe {

    public SecretKeySpec forgeCurbPinSigil(String curbPinDial) {
        while (true) {
            StringBuilder curbPinMosaic = new StringBuilder();
            curbPinMosaic.append("k41_curbpin");
            curbPinMosaic.append(curbPinDial);
            String curbPinCrest = curbPinMosaic.toString();
            byte[] curbPinSkein = curbPinCrest.getBytes();
            SecretKeySpec curbPinSigil = new SecretKeySpec(curbPinSkein, "AES");
            return curbPinSigil;
        }
    }
}
