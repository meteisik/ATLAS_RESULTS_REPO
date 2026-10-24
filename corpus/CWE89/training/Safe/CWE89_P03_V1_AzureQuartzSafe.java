import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_AzureQuartzSafe {

    private void queryAzureQuartz(String data) throws SQLException {
        Connection azureQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureQuartz");
        Statement azureQuartzStatement = null;
        ResultSet azureQuartzRows = null;
        try {
            azureQuartzStatement = azureQuartzConnection.createStatement();
            azureQuartzRows = azureQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureQuartzRows.getRow());
        } finally {
            if (azureQuartzRows != null) {
                azureQuartzRows.close();
            }
            if (azureQuartzStatement != null) {
                azureQuartzStatement.close();
            }
            azureQuartzConnection.close();
        }
    }

    public void runAzureQuartz() throws SQLException {
        String data;
        data = "foo";
        queryAzureQuartz(data);
    }
}
