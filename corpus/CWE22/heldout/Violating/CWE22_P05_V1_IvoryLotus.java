import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V1_IvoryLotus {
    private String ivoryLotusData;

    private void readIvoryLotus() {
        String data = ivoryLotusData;
        String ivoryLotusRoot = "/home/user/uploads/";
        if (data != null) {
            File ivoryLotusFile = new File(ivoryLotusRoot + data);
            FileInputStream ivoryLotusStream = null;
            InputStreamReader ivoryLotusStreamReader = null;
            BufferedReader ivoryLotusReader = null;
            if (ivoryLotusFile.exists() && ivoryLotusFile.isFile()) {
                try {
                    ivoryLotusStream = new FileInputStream(ivoryLotusFile);
                    ivoryLotusStreamReader = new InputStreamReader(ivoryLotusStream, "UTF-8");
                    ivoryLotusReader = new BufferedReader(ivoryLotusStreamReader);
                    System.out.println(ivoryLotusReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V1_IvoryLotus").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (ivoryLotusReader != null) {
                            ivoryLotusReader.close();
                        }
                        if (ivoryLotusStreamReader != null) {
                            ivoryLotusStreamReader.close();
                        }
                        if (ivoryLotusStream != null) {
                            ivoryLotusStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V1_IvoryLotus").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openIvoryLotus() {
        String data;
        data = System.getenv("IVORY_LOTUS_PATH");
        ivoryLotusData = data;
        readIvoryLotus();
    }
}
