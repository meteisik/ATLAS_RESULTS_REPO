import java.util.logging.Logger;

public class CWE117_P02_V1_CrimsonLantern {

    public void handleCrimsonLantern() {
        String dataCopy;
        {
            String data;
            data = System.getenv("CRIMSON_LANTERN_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger crimsonLanternLogger = Logger.getLogger("crimsonLantern.audit");
            crimsonLanternLogger.info("Login attempt for user " + data);
        }
    }
}
