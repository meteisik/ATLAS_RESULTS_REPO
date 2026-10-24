import java.util.logging.Logger;

public class CWE117_P02_V1_CobaltRaven {

    public void handleCobaltRaven() {
        String dataCopy;
        {
            String data;
            data = System.getenv("COBALT_RAVEN_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger cobaltRavenLogger = Logger.getLogger("cobaltRaven.audit");
            cobaltRavenLogger.info("Login attempt for user " + data);
        }
    }
}
