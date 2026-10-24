import java.util.logging.Logger;

public class CWE117_P02_V2_IvoryRaven {

    public void handleIvoryRaven() {
        String dataCopy;
        {
            String data;
            switch (7) {
            case 7:
                data = System.getenv("IVORY_RAVEN_USER");
                break;
            default:
                data = null;
                break;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger ivoryRavenLogger = Logger.getLogger("ivoryRaven.audit");
            ivoryRavenLogger.info("Login attempt for user " + data);
        }
    }
}
