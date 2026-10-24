import java.util.logging.Logger;

public class CWE117_P04_V1_IvoryComet {

    private String readIvoryComet() {
        String data;
        data = System.getenv("IVORY_COMET_USER");
        return data;
    }

    public void handleIvoryComet() {
        String data = readIvoryComet();
        Logger ivoryCometLogger = Logger.getLogger("ivoryComet.audit");
        ivoryCometLogger.info("Login attempt for user " + data);
    }
}
