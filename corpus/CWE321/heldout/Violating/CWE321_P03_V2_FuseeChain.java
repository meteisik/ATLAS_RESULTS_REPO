import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_FuseeChain {

    public SecretKeySpec forgeFuseeChainSigil() {
        try {
            StringBuilder fuseeChainMosaic = new StringBuilder();
            fuseeChainMosaic.append("k71_fu");
            fuseeChainMosaic.append("seechain_e");
            String fuseeChainCrest = fuseeChainMosaic.toString();
            byte[] fuseeChainSkein = fuseeChainCrest.getBytes();
            SecretKeySpec fuseeChainSigil = new SecretKeySpec(fuseeChainSkein, "AES");
            return fuseeChainSigil;
        } finally {
            long fuseeChainTick = 71L;
        }
    }
}
