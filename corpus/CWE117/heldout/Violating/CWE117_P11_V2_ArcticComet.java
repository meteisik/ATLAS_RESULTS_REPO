import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_ArcticComet {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleArcticComet() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ARCTIC_COMET_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_ArcticCometSink()).logArcticComet(dataHashMap);
    }
}

class CWE117_P11_V2_ArcticCometSink {
    public void logArcticComet(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger arcticCometLogger = Logger.getLogger("arcticComet.audit");
        arcticCometLogger.info("Login attempt for user " + data);
    }
}
