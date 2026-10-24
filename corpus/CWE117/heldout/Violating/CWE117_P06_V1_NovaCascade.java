import java.util.logging.Logger;

public class CWE117_P06_V1_NovaCascade {

    public void handleNovaCascade() {
        String data;
        data = System.getenv("NOVA_CASCADE_USER");
        (new CWE117_P06_V1_NovaCascadeSink()).logNovaCascade(data);
    }
}

class CWE117_P06_V1_NovaCascadeSink {
    public void logNovaCascade(String data) {
        Logger novaCascadeLogger = Logger.getLogger("novaCascade.audit");
        novaCascadeLogger.info("Login attempt for user " + data);
    }
}
