import java.util.logging.Logger;

public class CWE117_P05_V1_IvoryComet {

    private String ivoryCometData;

    private void logIvoryComet() {
        String data = ivoryCometData;
        Logger ivoryCometLogger = Logger.getLogger("ivoryComet.audit");
        ivoryCometLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryComet() {
        String data;
        data = System.getenv("IVORY_COMET_USER");
        ivoryCometData = data;
        logIvoryComet();
    }
}
