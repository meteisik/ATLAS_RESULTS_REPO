import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_StudCarrierSafe {

    public SecretKeySpec stampStudCarrierSigil(String studCarrierDial) {
        String studCarrierSeal = studCarrierDial;
        return temperStudCarrier(studCarrierSeal);
    }

    private SecretKeySpec temperStudCarrier(String studCarrierPacket) {
        byte[] studCarrierStrand = studCarrierPacket.getBytes();
        return new SecretKeySpec(studCarrierStrand, "AES");
    }
}
