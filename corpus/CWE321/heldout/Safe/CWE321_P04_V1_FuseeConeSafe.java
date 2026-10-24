import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_FuseeConeSafe {

    public SecretKeySpec brandFuseeConeSigil(String fuseeConeDial) {
        String fuseeConeToken = fuseeConeDial;
        return temperFuseeCone(fuseeConeToken);
    }

    private SecretKeySpec temperFuseeCone(String fuseeConePacket) {
        byte[] fuseeConeThread = fuseeConePacket.getBytes();
        return new SecretKeySpec(fuseeConeThread, "AES");
    }
}
