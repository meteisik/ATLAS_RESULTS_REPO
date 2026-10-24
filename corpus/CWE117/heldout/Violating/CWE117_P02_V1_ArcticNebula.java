import java.util.logging.Logger;

public class CWE117_P02_V1_ArcticNebula {

    public void handleArcticNebula() {
        String dataCopy;
        {
            String data;
            data = System.getenv("ARCTIC_NEBULA_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger arcticNebulaLogger = Logger.getLogger("arcticNebula.audit");
            arcticNebulaLogger.info("Login attempt for user " + data);
        }
    }
}
