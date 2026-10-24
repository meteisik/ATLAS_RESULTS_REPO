import java.util.logging.Logger;

public class CWE117_P02_V1_CrimsonKestrel {

    public void handleCrimsonKestrel() {
        String dataCopy;
        {
            String data;
            data = System.getenv("CRIMSON_KESTREL_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger crimsonKestrelLogger = Logger.getLogger("crimsonKestrel.audit");
            crimsonKestrelLogger.info("Login attempt for user " + data);
        }
    }
}
