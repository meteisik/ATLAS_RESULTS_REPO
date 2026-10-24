import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_SilentLotus {

    public void openSilentLotus() {
        String data;
        data = System.getenv("SILENT_LOTUS_PATH");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_SilentLotusSink()).readSilentLotus(dataHashMap);
    }
}

class CWE22_P11_V1_SilentLotusSink {
    public void readSilentLotus(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String silentLotusRoot = "/home/user/uploads/";
        if (data != null) {
            File silentLotusFile = new File(silentLotusRoot + data);
            FileInputStream silentLotusStream = null;
            InputStreamReader silentLotusStreamReader = null;
            BufferedReader silentLotusReader = null;
            if (silentLotusFile.exists() && silentLotusFile.isFile()) {
                try {
                    silentLotusStream = new FileInputStream(silentLotusFile);
                    silentLotusStreamReader = new InputStreamReader(silentLotusStream, "UTF-8");
                    silentLotusReader = new BufferedReader(silentLotusStreamReader);
                    System.out.println(silentLotusReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V1_SilentLotusSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (silentLotusReader != null) {
                            silentLotusReader.close();
                        }
                        if (silentLotusStreamReader != null) {
                            silentLotusStreamReader.close();
                        }
                        if (silentLotusStream != null) {
                            silentLotusStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V1_SilentLotusSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
