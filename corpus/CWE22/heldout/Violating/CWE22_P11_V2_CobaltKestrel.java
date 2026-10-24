import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_CobaltKestrel {

    public void openCobaltKestrel() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("COBALT_KESTREL_PATH");
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_CobaltKestrelSink()).readCobaltKestrel(dataHashMap);
    }
}

class CWE22_P11_V2_CobaltKestrelSink {
    public void readCobaltKestrel(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String cobaltKestrelRoot = "/home/user/uploads/";
        if (data != null) {
            File cobaltKestrelFile = new File(cobaltKestrelRoot + data);
            FileInputStream cobaltKestrelStream = null;
            InputStreamReader cobaltKestrelStreamReader = null;
            BufferedReader cobaltKestrelReader = null;
            if (cobaltKestrelFile.exists() && cobaltKestrelFile.isFile()) {
                try {
                    cobaltKestrelStream = new FileInputStream(cobaltKestrelFile);
                    cobaltKestrelStreamReader = new InputStreamReader(cobaltKestrelStream, "UTF-8");
                    cobaltKestrelReader = new BufferedReader(cobaltKestrelStreamReader);
                    System.out.println(cobaltKestrelReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_CobaltKestrelSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (cobaltKestrelReader != null) {
                            cobaltKestrelReader.close();
                        }
                        if (cobaltKestrelStreamReader != null) {
                            cobaltKestrelStreamReader.close();
                        }
                        if (cobaltKestrelStream != null) {
                            cobaltKestrelStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_CobaltKestrelSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
