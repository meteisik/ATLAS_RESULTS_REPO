import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P03_V1_IvoryHarbor {

    private void readIvoryHarbor(String data) {
        String ivoryHarborRoot = "/home/user/uploads/";
        if (data != null) {
            File ivoryHarborFile = new File(ivoryHarborRoot + data);
            FileInputStream ivoryHarborStream = null;
            InputStreamReader ivoryHarborStreamReader = null;
            BufferedReader ivoryHarborReader = null;
            if (ivoryHarborFile.exists() && ivoryHarborFile.isFile()) {
                try {
                    ivoryHarborStream = new FileInputStream(ivoryHarborFile);
                    ivoryHarborStreamReader = new InputStreamReader(ivoryHarborStream, "UTF-8");
                    ivoryHarborReader = new BufferedReader(ivoryHarborStreamReader);
                    System.out.println(ivoryHarborReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P03_V1_IvoryHarbor").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (ivoryHarborReader != null) {
                            ivoryHarborReader.close();
                        }
                        if (ivoryHarborStreamReader != null) {
                            ivoryHarborStreamReader.close();
                        }
                        if (ivoryHarborStream != null) {
                            ivoryHarborStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P03_V1_IvoryHarbor").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openIvoryHarbor() {
        String data;
        data = System.getenv("IVORY_HARBOR_PATH");
        readIvoryHarbor(data);
    }
}
