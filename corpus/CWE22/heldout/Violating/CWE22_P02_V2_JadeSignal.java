import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V2_JadeSignal {
    private static boolean privateReturnsTrue() { return true; }

    public void openJadeSignal() {
        String dataCopy;
        {
            String data;
            if (privateReturnsTrue()) {
                data = System.getenv("JADE_SIGNAL_PATH");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String jadeSignalRoot = "/home/user/uploads/";
            if (data != null) {
                File jadeSignalFile = new File(jadeSignalRoot + data);
                FileInputStream jadeSignalStream = null;
                InputStreamReader jadeSignalStreamReader = null;
                BufferedReader jadeSignalReader = null;
                if (jadeSignalFile.exists() && jadeSignalFile.isFile()) {
                    try {
                        jadeSignalStream = new FileInputStream(jadeSignalFile);
                        jadeSignalStreamReader = new InputStreamReader(jadeSignalStream, "UTF-8");
                        jadeSignalReader = new BufferedReader(jadeSignalStreamReader);
                        System.out.println(jadeSignalReader.readLine());
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P02_V2_JadeSignal").log(Level.WARNING, "Error with stream reading", exceptIO);
                    } finally {
                        try {
                            if (jadeSignalReader != null) {
                                jadeSignalReader.close();
                            }
                            if (jadeSignalStreamReader != null) {
                                jadeSignalStreamReader.close();
                            }
                            if (jadeSignalStream != null) {
                                jadeSignalStream.close();
                            }
                        } catch (IOException exceptIO) {
                            Logger.getLogger("CWE22_P02_V2_JadeSignal").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}
