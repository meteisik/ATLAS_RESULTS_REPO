import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_AzureAuroraSafe {

    public void runAzureAurora() throws SQLException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
