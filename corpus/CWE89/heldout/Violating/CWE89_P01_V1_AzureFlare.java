import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_AzureFlare {

    public void runAzureFlare() throws SQLException {
        String data;
        data = System.getenv("AZURE_FLARE_FILTER");
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
