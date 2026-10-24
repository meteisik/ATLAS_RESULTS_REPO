import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_CrimsonCometSafe {
    private static int privateFive = 5;

    public void openCrimsonComet() {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_CrimsonCometSafeSink()).readCrimsonComet(dataHashMap);
    }
}

class CWE22_P11_V2_CrimsonCometSafeSink {
    public void readCrimsonComet(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String crimsonCometRoot = "/home/user/uploads/";
        if (data != null) {
            File crimsonCometFile = new File(crimsonCometRoot + data);
            FileInputStream crimsonCometStream = null;
            InputStreamReader crimsonCometStreamReader = null;
            BufferedReader crimsonCometReader = null;
            if (crimsonCometFile.exists() && crimsonCometFile.isFile()) {
                try {
                    crimsonCometStream = new FileInputStream(crimsonCometFile);
                    crimsonCometStreamReader = new InputStreamReader(crimsonCometStream, "UTF-8");
                    crimsonCometReader = new BufferedReader(crimsonCometStreamReader);
                    System.out.println(crimsonCometReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_CrimsonCometSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (crimsonCometReader != null) {
                            crimsonCometReader.close();
                        }
                        if (crimsonCometStreamReader != null) {
                            crimsonCometStreamReader.close();
                        }
                        if (crimsonCometStream != null) {
                            crimsonCometStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_CrimsonCometSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
