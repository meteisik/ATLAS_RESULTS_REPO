import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_AzureSignal {

    private void queryAzureSignal(String data) throws SQLException {
        Connection azureSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureSignal");
        Statement azureSignalStatement = null;
        ResultSet azureSignalRows = null;
        try {
            azureSignalStatement = azureSignalConnection.createStatement();
            azureSignalRows = azureSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureSignalRows.getRow());
        } finally {
            if (azureSignalRows != null) {
                azureSignalRows.close();
            }
            if (azureSignalStatement != null) {
                azureSignalStatement.close();
            }
            azureSignalConnection.close();
        }
    }

    public void runAzureSignal() throws SQLException {
        String data;
        data = System.getenv("AZURE_SIGNAL_FILTER");
        queryAzureSignal(data);
    }
}
