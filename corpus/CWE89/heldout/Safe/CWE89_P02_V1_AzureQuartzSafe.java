import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_AzureQuartzSafe {

    public void runAzureQuartz() throws SQLException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
    }
}
