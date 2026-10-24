import java.util.logging.Logger;

public class CWE117_P02_V1_CrimsonComet {

    public void handleCrimsonComet() {
        String dataCopy;
        {
            String data;
            data = System.getenv("CRIMSON_COMET_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger crimsonCometLogger = Logger.getLogger("crimsonComet.audit");
            crimsonCometLogger.info("Login attempt for user " + data);
        }
    }
}
