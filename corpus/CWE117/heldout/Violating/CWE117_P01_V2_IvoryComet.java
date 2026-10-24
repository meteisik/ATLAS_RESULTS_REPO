import java.util.logging.Logger;

public class CWE117_P01_V2_IvoryComet {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleIvoryComet() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("IVORY_COMET_USER");
        } else {
            data = null;
        }
        Logger ivoryCometLogger = Logger.getLogger("ivoryComet.audit");
        ivoryCometLogger.info("Login attempt for user " + data);
    }
}
