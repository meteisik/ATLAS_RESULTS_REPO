import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_StudCarrier {

    public SecretKeySpec mintStudCarrierSigil() {
        for (int studCarrierLap = 0; studCarrierLap < 1; studCarrierLap++) {
            String studCarrierBadge = "k62_studcarrier_";
            byte[] studCarrierFilament = studCarrierBadge.getBytes();
            SecretKeySpec studCarrierSigil = new SecretKeySpec(studCarrierFilament, "AES");
            return studCarrierSigil;
        }
        throw new IllegalStateException("studCarrier lap fault");
    }
}
