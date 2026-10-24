import java.util.logging.Logger;

public class CWE117_P10_V2_ArcticLotus {

    public static String data;

    public void handleArcticLotus() {
        while (true) {
            data = System.getenv("ARCTIC_LOTUS_USER");
            break;
        }
        (new CWE117_P10_V2_ArcticLotusSink()).logArcticLotus();
    }
}

class CWE117_P10_V2_ArcticLotusSink {
    public void logArcticLotus() {
        String data = CWE117_P10_V2_ArcticLotus.data;
        Logger arcticLotusLogger = Logger.getLogger("arcticLotus.audit");
        arcticLotusLogger.info("Login attempt for user " + data);
    }
}
