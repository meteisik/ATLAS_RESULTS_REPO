import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class CWE22_P03_V1_AzureQuartzSafe {

    private void readAzureQuartz(String data) throws IOException {
        String azureQuartzRoot = "/home/user/uploads/";
        File azureQuartzFile = new File(azureQuartzRoot + data);
        FileInputStream azureQuartzStream = new FileInputStream(azureQuartzFile);
        azureQuartzStream.close();
    }

    public void openAzureQuartz() throws IOException {
        String data;
        data = "foo";
        readAzureQuartz(data);
    }
}
