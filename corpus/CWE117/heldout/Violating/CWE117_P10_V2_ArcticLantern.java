import java.util.logging.Logger;

public class CWE117_P10_V2_ArcticLantern {

    public static String data;

    public void handleArcticLantern() {
        switch (7) {
        case 7:
            data = System.getenv("ARCTIC_LANTERN_USER");
            break;
        default:
            data = null;
            break;
        }
        (new CWE117_P10_V2_ArcticLanternSink()).logArcticLantern();
    }
}

class CWE117_P10_V2_ArcticLanternSink {
    public void logArcticLantern() {
        String data = CWE117_P10_V2_ArcticLantern.data;
        Logger arcticLanternLogger = Logger.getLogger("arcticLantern.audit");
        arcticLanternLogger.info("Login attempt for user " + data);
    }
}
