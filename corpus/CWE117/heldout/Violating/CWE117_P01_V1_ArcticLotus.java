import java.util.logging.Logger;

public class CWE117_P01_V1_ArcticLotus {

    public void handleArcticLotus() {
        String data;
        data = System.getenv("ARCTIC_LOTUS_USER");
        Logger arcticLotusLogger = Logger.getLogger("arcticLotus.audit");
        arcticLotusLogger.info("Login attempt for user " + data);
    }
}
