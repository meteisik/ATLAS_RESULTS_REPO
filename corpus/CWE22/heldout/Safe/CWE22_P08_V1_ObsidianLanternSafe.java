import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_ObsidianLanternSafe {

    public void openObsidianLantern() {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_ObsidianLanternSafeSink()).readObsidianLantern(dataArray);
    }
}

class CWE22_P08_V1_ObsidianLanternSafeSink {
    public void readObsidianLantern(String[] dataArray) {
        String data = dataArray[2];
        String obsidianLanternRoot = "/home/user/uploads/";
        if (data != null) {
            File obsidianLanternFile = new File(obsidianLanternRoot + data);
            FileInputStream obsidianLanternStream = null;
            InputStreamReader obsidianLanternStreamReader = null;
            BufferedReader obsidianLanternReader = null;
            if (obsidianLanternFile.exists() && obsidianLanternFile.isFile()) {
                try {
                    obsidianLanternStream = new FileInputStream(obsidianLanternFile);
                    obsidianLanternStreamReader = new InputStreamReader(obsidianLanternStream, "UTF-8");
                    obsidianLanternReader = new BufferedReader(obsidianLanternStreamReader);
                    System.out.println(obsidianLanternReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V1_ObsidianLanternSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (obsidianLanternReader != null) {
                            obsidianLanternReader.close();
                        }
                        if (obsidianLanternStreamReader != null) {
                            obsidianLanternStreamReader.close();
                        }
                        if (obsidianLanternStream != null) {
                            obsidianLanternStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V1_ObsidianLanternSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
