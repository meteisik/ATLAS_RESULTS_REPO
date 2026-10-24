import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_ArcticComet {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openArcticComet() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ARCTIC_COMET_PATH");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_ArcticCometSink()).readArcticComet(dataHashMap);
    }
}

class CWE22_P11_V2_ArcticCometSink {
    public void readArcticComet(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String arcticCometRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticCometFile = new File(arcticCometRoot + data);
            FileInputStream arcticCometStream = null;
            InputStreamReader arcticCometStreamReader = null;
            BufferedReader arcticCometReader = null;
            if (arcticCometFile.exists() && arcticCometFile.isFile()) {
                try {
                    arcticCometStream = new FileInputStream(arcticCometFile);
                    arcticCometStreamReader = new InputStreamReader(arcticCometStream, "UTF-8");
                    arcticCometReader = new BufferedReader(arcticCometStreamReader);
                    System.out.println(arcticCometReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_ArcticCometSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticCometReader != null) {
                            arcticCometReader.close();
                        }
                        if (arcticCometStreamReader != null) {
                            arcticCometStreamReader.close();
                        }
                        if (arcticCometStream != null) {
                            arcticCometStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_ArcticCometSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
