import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_ObsidianHarbor {

    public void openObsidianHarbor() {
        String data;
        data = System.getenv("OBSIDIAN_HARBOR_PATH");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_ObsidianHarborSink()).readObsidianHarbor(dataArray);
    }
}

class CWE22_P08_V1_ObsidianHarborSink {
    public void readObsidianHarbor(String[] dataArray) {
        String data = dataArray[2];
        String obsidianHarborRoot = "/home/user/uploads/";
        if (data != null) {
            File obsidianHarborFile = new File(obsidianHarborRoot + data);
            FileInputStream obsidianHarborStream = null;
            InputStreamReader obsidianHarborStreamReader = null;
            BufferedReader obsidianHarborReader = null;
            if (obsidianHarborFile.exists() && obsidianHarborFile.isFile()) {
                try {
                    obsidianHarborStream = new FileInputStream(obsidianHarborFile);
                    obsidianHarborStreamReader = new InputStreamReader(obsidianHarborStream, "UTF-8");
                    obsidianHarborReader = new BufferedReader(obsidianHarborStreamReader);
                    System.out.println(obsidianHarborReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V1_ObsidianHarborSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (obsidianHarborReader != null) {
                            obsidianHarborReader.close();
                        }
                        if (obsidianHarborStreamReader != null) {
                            obsidianHarborStreamReader.close();
                        }
                        if (obsidianHarborStream != null) {
                            obsidianHarborStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V1_ObsidianHarborSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
