import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_FuseeChainSafe {

    public SecretKeySpec forgeFuseeChainSigil(String fuseeChainDial) {
        try {
            StringBuilder fuseeChainMosaic = new StringBuilder();
            fuseeChainMosaic.append("k71_fu");
            fuseeChainMosaic.append(fuseeChainDial);
            String fuseeChainCrest = fuseeChainMosaic.toString();
            byte[] fuseeChainSkein = fuseeChainCrest.getBytes();
            SecretKeySpec fuseeChainSigil = new SecretKeySpec(fuseeChainSkein, "AES");
            return fuseeChainSigil;
        } finally {
            long fuseeChainTick = 71L;
        }
    }
}
