import java.util.logging.Logger;

public class CWE117_P02_V1_CrimsonNebula {

    public void handleCrimsonNebula() {
        String dataCopy;
        {
            String data;
            data = System.getenv("CRIMSON_NEBULA_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger crimsonNebulaLogger = Logger.getLogger("crimsonNebula.audit");
            crimsonNebulaLogger.info("Login attempt for user " + data);
        }
    }
}
