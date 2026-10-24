import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V2_ObsidianRaven {

    public void openObsidianRaven() {
        String data;
        if (true) {
            data = System.getenv("OBSIDIAN_RAVEN_PATH");
        } else {
            data = null;
        }
        (new CWE22_P06_V2_ObsidianRavenSink()).readObsidianRaven(data);
    }
}

class CWE22_P06_V2_ObsidianRavenSink {
    public void readObsidianRaven(String data) {
        String obsidianRavenRoot = "/home/user/uploads/";
        if (data != null) {
            File obsidianRavenFile = new File(obsidianRavenRoot + data);
            FileInputStream obsidianRavenStream = null;
            InputStreamReader obsidianRavenStreamReader = null;
            BufferedReader obsidianRavenReader = null;
            if (obsidianRavenFile.exists() && obsidianRavenFile.isFile()) {
                try {
                    obsidianRavenStream = new FileInputStream(obsidianRavenFile);
                    obsidianRavenStreamReader = new InputStreamReader(obsidianRavenStream, "UTF-8");
                    obsidianRavenReader = new BufferedReader(obsidianRavenStreamReader);
                    System.out.println(obsidianRavenReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V2_ObsidianRavenSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (obsidianRavenReader != null) {
                            obsidianRavenReader.close();
                        }
                        if (obsidianRavenStreamReader != null) {
                            obsidianRavenStreamReader.close();
                        }
                        if (obsidianRavenStream != null) {
                            obsidianRavenStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V2_ObsidianRavenSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
