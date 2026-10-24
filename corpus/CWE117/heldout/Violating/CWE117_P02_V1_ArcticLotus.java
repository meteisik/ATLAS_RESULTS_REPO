import java.util.logging.Logger;

public class CWE117_P02_V1_ArcticLotus {

    public void handleArcticLotus() {
        String dataCopy;
        {
            String data;
            data = System.getenv("ARCTIC_LOTUS_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger arcticLotusLogger = Logger.getLogger("arcticLotus.audit");
            arcticLotusLogger.info("Login attempt for user " + data);
        }
    }
}
