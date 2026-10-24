import java.util.logging.Logger;

public class CWE117_P02_V2_JadeAurora {

    public void handleJadeAurora() {
        String dataCopy;
        {
            String data;
            while (true) {
                data = System.getenv("JADE_AURORA_USER");
                break;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger jadeAuroraLogger = Logger.getLogger("jadeAurora.audit");
            jadeAuroraLogger.info("Login attempt for user " + data);
        }
    }
}
