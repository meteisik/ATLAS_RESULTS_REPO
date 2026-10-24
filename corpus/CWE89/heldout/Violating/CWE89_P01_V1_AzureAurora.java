import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_AzureAurora {

    public void runAzureAurora() throws SQLException {
        String data;
        data = System.getenv("AZURE_AURORA_FILTER");
        Connection azureAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureAurora");
        Statement azureAuroraStatement = null;
        ResultSet azureAuroraRows = null;
        try {
            azureAuroraStatement = azureAuroraConnection.createStatement();
            azureAuroraRows = azureAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureAuroraRows.getRow());
        } finally {
            if (azureAuroraRows != null) {
                azureAuroraRows.close();
            }
            if (azureAuroraStatement != null) {
                azureAuroraStatement.close();
            }
            azureAuroraConnection.close();
        }
    }
}
