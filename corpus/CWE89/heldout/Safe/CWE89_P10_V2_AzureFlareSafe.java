import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AzureFlareSafe {
    private static int privateFive = 5;

    public static String data;

    public void runAzureFlare() throws SQLException {
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P10_V2_AzureFlareSafeSink()).queryAzureFlare();
    }
}

class CWE89_P10_V2_AzureFlareSafeSink {
    public void queryAzureFlare() throws SQLException {
        String data = CWE89_P10_V2_AzureFlareSafe.data;
        Connection azureFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureFlare");
        Statement azureFlareStatement = null;
        ResultSet azureFlareRows = null;
        try {
            azureFlareStatement = azureFlareConnection.createStatement();
            azureFlareRows = azureFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureFlareRows.getRow());
        } finally {
            if (azureFlareRows != null) {
                azureFlareRows.close();
            }
            if (azureFlareStatement != null) {
                azureFlareStatement.close();
            }
            azureFlareConnection.close();
        }
    }
}
