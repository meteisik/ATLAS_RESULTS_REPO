import java.util.logging.Logger;

public class CWE117_P05_V1_NovaCascade {

    private String novaCascadeData;

    private void logNovaCascade() {
        String data = novaCascadeData;
        Logger novaCascadeLogger = Logger.getLogger("novaCascade.audit");
        novaCascadeLogger.info("Login attempt for user " + data);
    }

    public void handleNovaCascade() {
        String data;
        data = System.getenv("NOVA_CASCADE_USER");
        novaCascadeData = data;
        logNovaCascade();
    }
}
