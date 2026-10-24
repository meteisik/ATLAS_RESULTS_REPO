import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_FuseeCone {

    public SecretKeySpec brandFuseeConeSigil() {
        String fuseeConeToken = "k13_fuseecone_es";
        return temperFuseeCone(fuseeConeToken);
    }

    private SecretKeySpec temperFuseeCone(String fuseeConePacket) {
        byte[] fuseeConeThread = fuseeConePacket.getBytes();
        return new SecretKeySpec(fuseeConeThread, "AES");
    }
}
