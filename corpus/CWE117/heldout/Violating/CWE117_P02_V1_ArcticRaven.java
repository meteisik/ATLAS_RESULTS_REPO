import java.util.logging.Logger;

public class CWE117_P02_V1_ArcticRaven {

    public void handleArcticRaven() {
        String dataCopy;
        {
            String data;
            data = System.getenv("ARCTIC_RAVEN_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger arcticRavenLogger = Logger.getLogger("arcticRaven.audit");
            arcticRavenLogger.info("Login attempt for user " + data);
        }
    }
}
