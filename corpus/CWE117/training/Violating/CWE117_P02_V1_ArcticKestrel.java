import java.util.logging.Logger;

public class CWE117_P02_V1_ArcticKestrel {

    public void handleArcticKestrel() {
        String dataCopy;
        {
            String data;
            data = System.getenv("ARCTIC_KESTREL_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger arcticKestrelLogger = Logger.getLogger("arcticKestrel.audit");
            arcticKestrelLogger.info("Login attempt for user " + data);
        }
    }
}
