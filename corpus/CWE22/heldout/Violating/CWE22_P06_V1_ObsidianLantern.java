import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V1_ObsidianLantern {

    public void openObsidianLantern() {
        String data;
        data = System.getenv("OBSIDIAN_LANTERN_PATH");
        (new CWE22_P06_V1_ObsidianLanternSink()).readObsidianLantern(data);
    }
}

class CWE22_P06_V1_ObsidianLanternSink {
    public void readObsidianLantern(String data) {
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
                    Logger.getLogger("CWE22_P06_V1_ObsidianLanternSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P06_V1_ObsidianLanternSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
