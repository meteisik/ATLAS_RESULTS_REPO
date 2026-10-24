import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_Chronograph {

    public SecretKeySpec stampChronographSigil() {
        StringBuilder chronographMosaic = new StringBuilder();
        chronographMosaic.append("k10_chro");
        chronographMosaic.append("nograph_");
        String chronographSeal = chronographMosaic.toString();
        byte[] chronographStrand = chronographSeal.getBytes();
        SecretKeySpec chronographSigil = new SecretKeySpec(chronographStrand, "AES");
        return chronographSigil;
    }
}
