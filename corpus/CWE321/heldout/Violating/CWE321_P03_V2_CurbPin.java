import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_CurbPin {

    public SecretKeySpec forgeCurbPinSigil() {
        while (true) {
            StringBuilder curbPinMosaic = new StringBuilder();
            curbPinMosaic.append("k41_curbpin");
            curbPinMosaic.append("_esca");
            String curbPinCrest = curbPinMosaic.toString();
            byte[] curbPinSkein = curbPinCrest.getBytes();
            SecretKeySpec curbPinSigil = new SecretKeySpec(curbPinSkein, "AES");
            return curbPinSigil;
        }
    }
}
