import java.util.logging.Logger;

public class CWE117_P02_V1_ArcticLantern {

    public void handleArcticLantern() {
        String dataCopy;
        {
            String data;
            data = System.getenv("ARCTIC_LANTERN_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger arcticLanternLogger = Logger.getLogger("arcticLantern.audit");
            arcticLanternLogger.info("Login attempt for user " + data);
        }
    }
}
