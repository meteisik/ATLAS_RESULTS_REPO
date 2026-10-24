import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_DetentEscapementSafe {

    public SecretKeySpec coinDetentEscapementSigil(String detentEscapementDial) {
        while (true) {
            String detentEscapementMarque = detentEscapementDial;
            byte[] detentEscapementPlait = detentEscapementMarque.getBytes();
            SecretKeySpec detentEscapementSigil = new SecretKeySpec(detentEscapementPlait, "AES");
            return detentEscapementSigil;
        }
    }
}
