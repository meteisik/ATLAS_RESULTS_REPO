import java.util.logging.Logger;

public class CWE117_P07_V1_NovaCascade {

    public void handleNovaCascade() {
        String data;
        data = (new CWE117_P07_V1_NovaCascadeSource()).readNovaCascade();
        Logger novaCascadeLogger = Logger.getLogger("novaCascade.audit");
        novaCascadeLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_NovaCascadeSource {
    public String readNovaCascade() {
        String data;
        data = System.getenv("NOVA_CASCADE_USER");
        return data;
    }
}
