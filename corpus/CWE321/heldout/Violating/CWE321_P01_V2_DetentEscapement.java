import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_DetentEscapement {

    public SecretKeySpec coinDetentEscapementSigil() {
        while (true) {
            String detentEscapementMarque = "k69_detentescape";
            byte[] detentEscapementPlait = detentEscapementMarque.getBytes();
            SecretKeySpec detentEscapementSigil = new SecretKeySpec(detentEscapementPlait, "AES");
            return detentEscapementSigil;
        }
    }
}
