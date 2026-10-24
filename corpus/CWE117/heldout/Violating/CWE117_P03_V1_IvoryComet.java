import java.util.logging.Logger;

public class CWE117_P03_V1_IvoryComet {

    private void logIvoryComet(String data) {
        Logger ivoryCometLogger = Logger.getLogger("ivoryComet.audit");
        ivoryCometLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryComet() {
        String data;
        data = System.getenv("IVORY_COMET_USER");
        logIvoryComet(data);
    }
}
