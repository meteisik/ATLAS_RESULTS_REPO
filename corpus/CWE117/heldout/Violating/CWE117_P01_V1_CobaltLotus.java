import java.util.logging.Logger;

public class CWE117_P01_V1_CobaltLotus {

    public void handleCobaltLotus() {
        String data;
        data = System.getenv("COBALT_LOTUS_USER");
        Logger cobaltLotusLogger = Logger.getLogger("cobaltLotus.audit");
        cobaltLotusLogger.info("Login attempt for user " + data);
    }
}
