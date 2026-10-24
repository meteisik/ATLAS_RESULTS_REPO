import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_CobaltOrbit {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void openCobaltOrbit() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("COBALT_ORBIT_PATH");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_CobaltOrbitSink()).readCobaltOrbit(dataHashMap);
    }
}

class CWE22_P11_V2_CobaltOrbitSink {
    public void readCobaltOrbit(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String cobaltOrbitRoot = "/home/user/uploads/";
        if (data != null) {
            File cobaltOrbitFile = new File(cobaltOrbitRoot + data);
            FileInputStream cobaltOrbitStream = null;
            InputStreamReader cobaltOrbitStreamReader = null;
            BufferedReader cobaltOrbitReader = null;
            if (cobaltOrbitFile.exists() && cobaltOrbitFile.isFile()) {
                try {
                    cobaltOrbitStream = new FileInputStream(cobaltOrbitFile);
                    cobaltOrbitStreamReader = new InputStreamReader(cobaltOrbitStream, "UTF-8");
                    cobaltOrbitReader = new BufferedReader(cobaltOrbitStreamReader);
                    System.out.println(cobaltOrbitReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_CobaltOrbitSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (cobaltOrbitReader != null) {
                            cobaltOrbitReader.close();
                        }
                        if (cobaltOrbitStreamReader != null) {
                            cobaltOrbitStreamReader.close();
                        }
                        if (cobaltOrbitStream != null) {
                            cobaltOrbitStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_CobaltOrbitSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
