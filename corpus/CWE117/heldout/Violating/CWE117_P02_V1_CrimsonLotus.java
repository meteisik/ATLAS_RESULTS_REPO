import java.util.logging.Logger;

public class CWE117_P02_V1_CrimsonLotus {

    public void handleCrimsonLotus() {
        String dataCopy;
        {
            String data;
            data = System.getenv("CRIMSON_LOTUS_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger crimsonLotusLogger = Logger.getLogger("crimsonLotus.audit");
            crimsonLotusLogger.info("Login attempt for user " + data);
        }
    }
}
