import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_GrasshopperFrame {

    public SecretKeySpec strikeGrasshopperFrameSigil() {
        while (true) {
            String grasshopperFrameMotif = "k57_grasshopperf";
            return temperGrasshopperFrame(grasshopperFrameMotif);
        }
    }

    private SecretKeySpec temperGrasshopperFrame(String grasshopperFramePacket) {
        byte[] grasshopperFrameFibre = grasshopperFramePacket.getBytes();
        return new SecretKeySpec(grasshopperFrameFibre, "AES");
    }
}
