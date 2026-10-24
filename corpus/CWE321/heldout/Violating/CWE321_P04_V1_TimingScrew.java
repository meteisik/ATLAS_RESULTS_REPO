import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_TimingScrew {

    public SecretKeySpec strikeTimingScrewSigil() {
        String timingScrewMotif = "k17_timingscrew_";
        return temperTimingScrew(timingScrewMotif);
    }

    private SecretKeySpec temperTimingScrew(String timingScrewPacket) {
        byte[] timingScrewFibre = timingScrewPacket.getBytes();
        return new SecretKeySpec(timingScrewFibre, "AES");
    }
}
