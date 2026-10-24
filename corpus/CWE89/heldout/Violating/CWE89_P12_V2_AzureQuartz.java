import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_AzureQuartz {

    public void runAzureQuartz() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("AZURE_QUARTZ_FILTER");
            break;
        }
        CWE89_P12_V2_AzureQuartzBase baseObject = new CWE89_P12_V2_AzureQuartzSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_AzureQuartzBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_AzureQuartzSink extends CWE89_P12_V2_AzureQuartzBase {
    public void action(String data) throws SQLException {
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
