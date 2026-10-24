import java.util.logging.Logger;

public class CWE117_P02_V2_IvoryComet {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleIvoryComet() {
        String dataCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_FIVE == 5) {
                data = System.getenv("IVORY_COMET_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger ivoryCometLogger = Logger.getLogger("ivoryComet.audit");
            ivoryCometLogger.info("Login attempt for user " + data);
        }
    }
}
