import java.util.logging.Logger;

public class CWE117_P05_V1_JadeCascade {

    private String jadeCascadeData;

    private void logJadeCascade() {
        String data = jadeCascadeData;
        Logger jadeCascadeLogger = Logger.getLogger("jadeCascade.audit");
        jadeCascadeLogger.info("Login attempt for user " + data);
    }

    public void handleJadeCascade() {
        String data;
        data = System.getenv("JADE_CASCADE_USER");
        jadeCascadeData = data;
        logJadeCascade();
    }
}
