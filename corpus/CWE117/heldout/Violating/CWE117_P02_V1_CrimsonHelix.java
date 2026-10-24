import java.util.logging.Logger;

public class CWE117_P02_V1_CrimsonHelix {

    public void handleCrimsonHelix() {
        String dataCopy;
        {
            String data;
            data = System.getenv("CRIMSON_HELIX_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger crimsonHelixLogger = Logger.getLogger("crimsonHelix.audit");
            crimsonHelixLogger.info("Login attempt for user " + data);
        }
    }
}
