import java.util.logging.Logger;

public class CWE117_P04_V1_JadeCascade {

    private String readJadeCascade() {
        String data;
        data = System.getenv("JADE_CASCADE_USER");
        return data;
    }

    public void handleJadeCascade() {
        String data = readJadeCascade();
        Logger jadeCascadeLogger = Logger.getLogger("jadeCascade.audit");
        jadeCascadeLogger.info("Login attempt for user " + data);
    }
}
