import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_StudCarrier {

    public SecretKeySpec stampStudCarrierSigil() {
        String studCarrierSeal = "k30_studcarrier_";
        return temperStudCarrier(studCarrierSeal);
    }

    private SecretKeySpec temperStudCarrier(String studCarrierPacket) {
        byte[] studCarrierStrand = studCarrierPacket.getBytes();
        return new SecretKeySpec(studCarrierStrand, "AES");
    }
}
